package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"server/internal/net/http"
)

// DefaultAddress is the default listener address.
const DefaultAddress string = "127.0.0.1:8887"

// ConfigurationHeaderKey is the name of the header field that contains the RoundTripper configuration.
// Note that this key can only start with one capital letter and the rest in lowercase.
// Unfortunately, this seems to be a limitation of Burp's Extender API.
const ConfigurationHeaderKey = "Goroundtripperconfig"

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
	m.HandleFunc("/", func(respWriter http.ResponseWriter, req *http.Request) {
		configHeader := req.Header.Get(ConfigurationHeaderKey)

		rt, err := NewRoundTripperFromJson(configHeader)
		if err != nil {
			writeError(respWriter, err)
			return
		}

		req.Header.Del(ConfigurationHeaderKey)

		res, err := rt.RoundTrip(req)
		if err != nil {
			writeError(respWriter, err)
			return
		}
		defer res.Body.Close()

		// Write the response (back to burp).
		for key, _ := range res.Header {
			values := res.Header.Values(key)
			for _, val := range values {
				respWriter.Header().Add(key, val)
			}
		}
		respWriter.WriteHeader(res.StatusCode)
		body, _ := io.ReadAll(res.Body)
		respWriter.Write(body)
	})

	s.Addr = addr
	s.Handler = m
	s.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{
			tls.Certificate{
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
