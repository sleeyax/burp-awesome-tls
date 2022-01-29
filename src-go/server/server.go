package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"server/internal/net/http"
)

const DefaultAddress string = "127.0.0.1:8887"

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
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// TODO: get the party started!
		fmt.Fprintf(w, "hello from Go!")
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
