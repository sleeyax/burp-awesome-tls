package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"

	"server/internal"

	http "github.com/ooni/oohttp"
)

const (
	// DefaultInterceptProxyAddress is the default intercept proxy listener address.
	DefaultInterceptProxyAddress string = "127.0.0.1:8886"
	// DefaultBurpProxyAddress is the default burp proxy listener address.
	DefaultBurpProxyAddress string = "127.0.0.1:8080"
	// DefaultSpoofProxyAddress is the default spoof proxy listener address.
	DefaultSpoofProxyAddress string = "127.0.0.1:8887"
)

// ConfigurationHeaderKey is the name of the header field that contains the RoundTripper configuration.
// Note that this key can only start with one capital letter and the rest in lowercase.
// Unfortunately, this seems to be a limitation of Burp's Extender API.
const ConfigurationHeaderKey = "Awesometlsconfig"

var (
	s         *http.Server
	proxy     *interceptProxy
	isProxyOn bool
)

func init() {
	s = &http.Server{}
}

func StartServer(addr string) error {
	s = &http.Server{}

	ca, private, err := NewCertificateAuthority()
	if err != nil {
		return fmt.Errorf("NewCertificateAuthority, err: %w", err)
	}

	m := http.NewServeMux()
	m.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		http.EnableHeaderOrder(w)

		configHeader := req.Header.Get(ConfigurationHeaderKey)
		req.Header.Del(ConfigurationHeaderKey)

		config, err := internal.ParseRequestConfig(configHeader)
		if err != nil {
			writeError(w, err)
			return
		}

		transport, err := internal.NewTransport(proxy.getTLSFingerprint)
		if err != nil {
			writeError(w, err)
			return
		}

		req.URL.Host = config.Host
		req.URL.Scheme = config.Scheme
		if strings.HasPrefix(string(internal.DefaultConfig.Fingerprint), "Chrome") {
			pHeaderOrder := []string{":method", ":authority", ":scheme", ":path"}
			for _, pHeader := range pHeaderOrder {
				req.Header.Add(http.PHeaderOrderKey, pHeader)
			}
		}

		res, err := transport.RoundTrip(req)
		if err != nil {
			writeError(w, err)
			return
		}

		defer res.Body.Close()

		// Write the response (back to burp).
		for k := range res.Header {
			vv := res.Header.Values(k)
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}

		w.WriteHeader(res.StatusCode)

		body, _ := io.ReadAll(res.Body)
		w.Write(body)
	})

	s.Addr = addr
	s.Handler = m
	s.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{ca.Raw},
				PrivateKey:  private,
				Leaf:        ca,
			},
		},
		NextProtos: []string{"http/1.1", "h2"},
	}

	listener, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("listen, err: %w", err)
	}

	tlsListener := tls.NewListener(listener, s.TLSConfig)

	if err := s.Serve(tlsListener); err != nil {
		return fmt.Errorf("serve, err: %w", err)
	}

	return nil
}

func SaveSettings(configJson string) error {
	config, err := internal.ParseTransportConfig(configJson)
	if err != nil {
		return err
	}

	if !isProxyOn && config.UseInterceptedFingerprint {
		if err = StartProxy(config.InterceptProxyAddr, config.BurpAddr); err != nil {
			return err
		}
		isProxyOn = true
	} else if isProxyOn && !config.UseInterceptedFingerprint {
		if err = StopProxy(); err != nil {
			return err
		}
		isProxyOn = false
	}

	internal.DefaultConfig = *config

	return nil
}

func StartProxy(interceptAddr, burpAddr string) (err error) {
	p, err := newInterceptProxy(interceptAddr, burpAddr)
	if err != nil {
		return err
	}

	proxy = p

	go proxy.Start()

	return nil
}

func StopProxy() (err error) {
	if proxy == nil {
		return nil
	}
	return proxy.Stop()
}

func StopServer() error {
	return s.Shutdown(context.Background())
}

func writeError(w http.ResponseWriter, err error) {
	w.WriteHeader(500)
	fmt.Fprint(w, fmt.Errorf("Awesome TLS error: %s", err))
	fmt.Println(err)
}
