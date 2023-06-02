package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	utls "github.com/refraction-networking/utls"
	"log"
	"net"
	"time"
)

// DefaultNetDialer is the default [net.Dialer].
var DefaultNetDialer = &net.Dialer{
	Timeout:   30 * time.Second,
	KeepAlive: 30 * time.Second,
}

// Dialer is a dialer that uses UTLS.
type Dialer struct {
	// Config is the OPTIONAL Config. In case it's not nil, we will
	// pass this config to [Factory] rather than a default one.
	Config *tls.Config

	// UTLS parrot to use.
	ClientHelloID *utls.ClientHelloID

	// beforeHandshakeFunc is a function called before the
	// TLS handshake, which is only useful for testing.
	beforeHandshakeFunc func()
}

// DialTLSContext dials a TLS connection using UTLS.
func (d *Dialer) DialTLSContext(ctx context.Context, network string, addr string) (net.Conn, error) {
	conn, err := DefaultNetDialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	sni, _, err := net.SplitHostPort(addr)
	if err != nil {
		panic(fmt.Sprintf("%s: %e", "net.SplitHostPort failed", err)) // cannot fail after successful dial
	}

	config := &tls.Config{ServerName: sni}
	if d.Config != nil {
		config = d.Config // as documented
	}

	if d.beforeHandshakeFunc != nil {
		d.beforeHandshakeFunc() // useful for testing
	}

	adapter := (&FactoryWithClientHelloId{d.ClientHelloID}).NewUTLSConn(conn, config)
	if err = adapter.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}

	proto := adapter.ConnectionState().NegotiatedProtocol

	log.Printf("negotiated protocol: %s", proto)

	return adapter, nil
}
