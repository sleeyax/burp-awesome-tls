package server

import (
	"context"
	"fmt"
	"net/http"
)

const DefaultAddress string = "127.0.0.1:8887"

var s *http.Server

func init() {
	s = &http.Server{}
}

func StartServer(addr string) error {
	m := http.NewServeMux()
	s.Addr = addr
	s.Handler = m

	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// TODO: get the party started!
		fmt.Fprintf(w, "hello from Go!")
	})

	return s.ListenAndServe()
}

func StopServer() error {
	return s.Shutdown(context.Background())
}
