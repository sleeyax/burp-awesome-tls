package tls

import (
	"crypto/tls"
	"net"

	oohttp "github.com/ooni/oohttp"
	utls "github.com/refraction-networking/utls"
)

// DefaultClientHelloID is the default [utls.ClientHelloID].
var DefaultClientHelloID = &utls.HelloChrome_Auto

// ConnFactory is a factory for creating UTLS connections.
type ConnFactory interface {
	// NewUTLSConn creates a new UTLS connection.
	// The conn and config arguments MUST NOT be nil.
	NewUTLSConn(conn net.Conn, config *tls.Config) oohttp.TLSConn
}

// FactoryWithClientHelloId implements ConnFactory.
type FactoryWithClientHelloId struct {
	// The TLS client hello id (fingerprint) to use.
	// Defaults to [DefaultClientHelloID].
	GetClientHello func(sni string) (*utls.ClientHelloID, *utls.ClientHelloSpec)
}

// NewUTLSConn implements ConnFactory.
func (f *FactoryWithClientHelloId) NewUTLSConn(conn net.Conn, config *tls.Config) oohttp.TLSConn {
	uConfig := &utls.Config{
		RootCAs:                     config.RootCAs,
		NextProtos:                  config.NextProtos,
		ServerName:                  config.ServerName,
		DynamicRecordSizingDisabled: config.DynamicRecordSizingDisabled,
		InsecureSkipVerify:          true,
	}

	clientHelloID, spec := f.GetClientHello(config.ServerName)

	return &uconnAdapter{UConn: utls.UClient(conn, uConfig, *clientHelloID), spec: spec}
}
