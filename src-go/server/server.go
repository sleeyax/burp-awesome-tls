package server

import (
	"context"
	"crypto/tls"
	"fmt"
	http "github.com/ooni/oohttp"
	"io"
	"net"
	"server/internal"
	"strings"
)

// DefaultAddress is the default listener address.
const DefaultAddress string = "127.0.0.1:8887"

// ConfigurationHeaderKey is the name of the header field that contains the RoundTripper configuration.
// Note that this key can only start with one capital letter and the rest in lowercase.
// Unfortunately, this seems to be a limitation of Burp's Extender API.
const ConfigurationHeaderKey = "Awesometlsconfig"

var s *http.Server

func init() {
	s = &http.Server{}
}

func StartServer(addr string) error {
	ca, private, err := NewCertificateAuthority()
	if err != nil {
		return err
	}

	m := http.NewServeMux()
	m.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		http.EnableHeaderOrder(w)

		configHeader := req.Header.Get(ConfigurationHeaderKey)
		req.Header.Del(ConfigurationHeaderKey)

		config, err := internal.ParseTransportConfig(configHeader)
		if err != nil {
			writeError(w, err)
			return
		}

		transport := internal.NewTransport(config)

		req.URL.Host = config.Host
		req.URL.Scheme = config.Scheme
		if strings.HasPrefix(string(config.Fingerprint), "Chrome") {
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
		return err
	}

	tlsListener := tls.NewListener(listener, s.TLSConfig)

	return s.Serve(tlsListener)
}

func StopServer() error {
	return s.Shutdown(context.Background())
}

func writeError(w http.ResponseWriter, err error) {
	w.WriteHeader(500)
	fmt.Fprint(w, fmt.Errorf("Awesome TLS error: %s", err))
	fmt.Println(err)
}
