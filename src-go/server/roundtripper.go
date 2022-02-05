package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	utls "github.com/refraction-networking/utls"
	"net"
	"net/url"
	"server/internal/net/http"
	"server/internal/net/http2"
	"strings"
	"time"
)

type RoundTripper struct {
	// Base URL containing the details required to connect the destination server.
	//
	// Format: PROTOCOL://HOST:PORT
	//
	// Example: https://sleeyax.com:443
	Url string

	// Connection dial timeout.
	// Defaults to 10 seconds.
	Timeout time.Duration

	// Profile to use during TLS client hello handshake.
	// Defaults to Chrome83.
	TlsFingerprint Fingerprint

	// Optional Server Name Indication override.
	SNI string
}

func NewRoundTripper() *RoundTripper {
	return &RoundTripper{}
}

func NewRoundTripperFromJson(data string) (*RoundTripper, error) {
	rt := &RoundTripper{}

	if strings.TrimSpace(data) == "" {
		return rt, nil
	}

	// If the header is not found, or the unmarshal fails, we should still have a default configuration to work with.
	if err := json.Unmarshal([]byte(data), rt); err != nil {
		return nil, err
	}

	return rt, nil
}

func (r *RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// TODO(maybe): caching

	if int64(r.Timeout) == 0 {
		r.Timeout = time.Second * 10
	}

	// Update request URL to point to the destined server.
	u, err := url.Parse(r.Url)
	if err != nil {
		return nil, err
	}
	req.URL.Scheme = u.Scheme
	req.URL.Host = u.Hostname()

	// No need to configure the connection any further if we're using plain HTTP requests.
	if req.URL.Scheme == "http" {
		tr := &http.Transport{}
		return tr.RoundTrip(req)
	}

	dialConn, err := net.DialTimeout("tcp", toTCPAddress(req.URL), r.Timeout)
	if err != nil {
		return nil, err
	}

	config := &utls.Config{
		ServerName: req.Host,
	}

	tlsConn := utls.UClient(dialConn, config, utls.HelloCustom)
	if err = tlsConn.ApplyPreset(r.TlsFingerprint.ToSpec()); err != nil {
		return nil, err
	}
	if r.SNI != "" {
		tlsConn.SetSNI(r.SNI)
	}
	if err = tlsConn.Handshake(); err != nil {
		return nil, err
	}

	switch tlsConn.ConnectionState().NegotiatedProtocol {
	case http2.NextProtoTLS:
		h2 := http2.Transport{
			DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
				return tlsConn, nil
			},
		}
		return h2.RoundTrip(req)
	default:
		h1 := &http.Transport{
			DialTLSContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
				return tlsConn, nil
			},
		}
		return h1.RoundTrip(req)
	}
}
