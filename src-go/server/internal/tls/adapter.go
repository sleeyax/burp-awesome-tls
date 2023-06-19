package tls

import (
	"context"
	"crypto/tls"

	utls "github.com/refraction-networking/utls"
)

// uconnAdapter is an adapter from utls.UConn to oohttp.TLSConn.
type uconnAdapter struct {
	*utls.UConn
	spec *utls.ClientHelloSpec
}

// ConnectionState implements TLSConn's ConnectionState.
func (c *uconnAdapter) ConnectionState() tls.ConnectionState {
	uConnState := c.UConn.ConnectionState()

	return tls.ConnectionState{
		Version:                     uConnState.Version,
		HandshakeComplete:           uConnState.HandshakeComplete,
		CipherSuite:                 uConnState.CipherSuite,
		DidResume:                   uConnState.DidResume,
		NegotiatedProtocol:          uConnState.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  uConnState.NegotiatedProtocolIsMutual,
		ServerName:                  uConnState.ServerName,
		PeerCertificates:            uConnState.PeerCertificates,
		VerifiedChains:              uConnState.VerifiedChains,
		SignedCertificateTimestamps: uConnState.SignedCertificateTimestamps,
		OCSPResponse:                uConnState.OCSPResponse,
		TLSUnique:                   uConnState.TLSUnique,
	}
}

// HandshakeContext implements TLSConn's HandshakeContext.
func (c *uconnAdapter) HandshakeContext(ctx context.Context) error {
	if c.spec != nil {
		if err := c.UConn.ApplyPreset(c.spec); err != nil {
			return err
		}
	}

	ch := make(chan error, 1)

	go func() {
		ch <- c.UConn.Handshake()
	}()

	select {
	case err := <-ch:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
