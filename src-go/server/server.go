package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"

	fhttp "github.com/bogdanfinn/fhttp"
	utls "github.com/bogdanfinn/utls"
	"github.com/klauspost/compress/zstd"
)

// ConfigurationHeaderKey is the name of the header field that contains the RoundTripper configuration.
// Note that this key can only start with one capital letter and the rest in lowercase.
// Unfortunately, this seems to be a limitation of Burp's Extender API.
const ConfigurationHeaderKey = "Awesometlsconfig"

var (
	s         *fhttp.Server
	proxy     *interceptProxy
	isProxyOn bool
)

func init() {
	s = &fhttp.Server{}
}

func StartServer(addr string) error {
	if addr == "" {
		return fmt.Errorf("address must be provided")
	}

	logMsg(fmt.Sprintf("Go server starting on %s...", addr))

	s = &fhttp.Server{}

	ca, private, err := NewCertificateAuthority()
	if err != nil {
		return fmt.Errorf("NewCertificateAuthority, err: %w", err)
	}

	m := fhttp.NewServeMux()
	m.HandleFunc("/", func(w fhttp.ResponseWriter, req *fhttp.Request) {
		configHeader := req.Header.Get(ConfigurationHeaderKey)
		req.Header.Del(ConfigurationHeaderKey)

		config, err := ParseTransportConfig(configHeader)
		if err != nil {
			writeError(w, err)
			return
		}

		if !isProxyOn && config.UseInterceptedFingerprint {
			if err = StartProxy(config.InterceptProxyAddr, config.BurpAddr); err != nil {
				writeError(w, err)
				return
			}
			isProxyOn = true
		} else if isProxyOn && !config.UseInterceptedFingerprint {
			if err = StopProxy(); err != nil {
				writeError(w, err)
				return
			}
			isProxyOn = false
		}

		if proxy != nil {
			if interceptedFingerprint := proxy.getTLSFingerprint(); interceptedFingerprint != "" && config.UseInterceptedFingerprint {
				config.HexClientHello = HexClientHello(interceptedFingerprint)
			}
		}

		client, err := NewClient(config)
		if err != nil {
			writeError(w, err)
			return
		}

		req.URL.Host = config.Host
		req.URL.Scheme = config.Scheme
		req.RequestURI = ""
		req.Header[fhttp.HeaderOrderKey] = config.HeaderOrder
		// The content-length header is already set by the client (internally).
		// Leaving it here causes strange '400 bad request' errors from the destination, so we remove it.
		req.Header.Del("Content-Length")

		res, err := client.Do(req)
		if err != nil {
			if strings.Contains(err.Error(), "http: server gave HTTP response to HTTPS client") {
				logMsg("Warning: HTTPS handshake failed because server returned HTTP. Retrying with HTTP scheme...")
				req.URL.Scheme = "http"
				res, err = client.Do(req)
				if err != nil {
					writeError(w, err)
					return
				}
			} else {
				writeError(w, err)
				return
			}
		}

		defer res.Body.Close()

		if config.Debug {
			logMsg(fmt.Sprintf("Request URL: %s", req.URL.String()))
			logMsg(fmt.Sprintf("Response Status: %s", res.Status))

			var headersBuilder strings.Builder
			headersBuilder.WriteString("Response Headers: ")
			for k, v := range res.Header {
				headersBuilder.WriteString(fmt.Sprintf("[%s: %s] ", k, strings.Join(v, ", ")))
			}
			logMsg(headersBuilder.String())
		}

		var body []byte
		var errRead error

		// If tls-client already decompressed it (Uncompressed=true) or if headers say zstd
		useZstd := strings.EqualFold(res.Header.Get("Content-Encoding"), "zstd") && !res.Uncompressed

		if useZstd {
			// Read all compressed bytes first to allow fallback
			compressedBytes, err := io.ReadAll(res.Body)
			if err != nil {
				writeError(w, err)
				return
			}

			// Try to decompress
			decoder, err := zstd.NewReader(bytes.NewReader(compressedBytes))
			if err == nil {
				body, errRead = io.ReadAll(decoder)
				decoder.Close()
			}

			if err != nil || errRead != nil {
				// If decompression failed, assume it might be already decompressed or invalid.
				// Log the warning but return the original bytes.
				logMsg(fmt.Sprintf("Warning: zstd decompression failed (magic: %x...), assuming already decompressed. Error: %v %v",
					safePeek(compressedBytes, 4), err, errRead))
				body = compressedBytes
			}

			// Always remove the header if we processed it (successfully or fallback)
			// to avoid browser errors if we are returning plaintext.
			res.Header.Del("Content-Encoding")
		} else {
			// Normal read
			body, errRead = io.ReadAll(res.Body)
			if errRead != nil {
				writeError(w, errRead)
				return
			}

			// If it was uncompressed by transport but header remains
			if res.Uncompressed && strings.EqualFold(res.Header.Get("Content-Encoding"), "zstd") {
				res.Header.Del("Content-Encoding")
			}
		}

		if errRead != nil {
			// specific read error not handled above
			writeError(w, errRead)
			return
		}

		if config.Debug {
			logMsg(fmt.Sprintf("Read Body Size: %d", len(body)))
		}

		// Write the response (back to burp).
		for k := range res.Header {
			vv := res.Header.Values(k)
			for _, v := range vv {
				// The response body is already automatically decompressed, so we need to update the Content-Length header accordingly.
				// Not doing so will cause the response writer to return an error.
				if k == "Content-Length" {
					w.Header().Add(k, fmt.Sprintf("%d", len(body)))
				} else {
					w.Header().Add(k, v)
				}
			}
		}
		w.WriteHeader(res.StatusCode)
		w.Write(body)
	})

	s.Addr = addr
	s.Handler = m
	s.TLSConfig = &utls.Config{
		Certificates: []utls.Certificate{
			{
				Certificate: [][]byte{ca.Raw},
				PrivateKey:  private,
				Leaf:        ca,
			},
		},
		NextProtos: []string{"http/1.1"},
	}

	listener, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("listen, err: %w", err)
	}

	tlsListener := utls.NewListener(listener, s.TLSConfig)

	if err := s.Serve(tlsListener); err != nil {
		return fmt.Errorf("serve, err: %w", err)
	}

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

func writeError(w fhttp.ResponseWriter, err error) {
	w.WriteHeader(500)
	fmt.Fprint(w, fmt.Sprintf("Awesome TLS error: %s", err))
	logMsg(err.Error())
}

var Logger func(string)

func logMsg(msg string) {
	if Logger != nil {
		Logger(msg)
	} else {
		fmt.Println(msg)

	}
}

func safePeek(data []byte, length int) []byte {
	if len(data) < length {
		return data
	}
	return data[:length]
}
