package internal

import (
	"encoding/json"
	"net"
	"strings"
	"time"

	internalTls "server/internal/tls"

	oohttp "github.com/ooni/oohttp"
	"github.com/pkg/errors"
)

const (
	DefaultHttpTimeout         = time.Duration(30) * time.Second
	DefaultHttpKeepAlive       = time.Duration(30) * time.Second
	DefaultIdleConnTimeout     = time.Duration(90) * time.Second
	DefaultTLSHandshakeTimeout = time.Duration(10) * time.Second
)

type TransportConfig struct {
	// Hostname to send the HTTP request to.
	Host string

	// HTTP or HTTPs.
	Scheme string

	// The TLS fingerprint to use.
	Fingerprint internalTls.Fingerprint

	// Hexadecimal Client Hello to use
	HexClientHello internalTls.HexClientHello

	// The maximum amount of time a dial will wait for a connect to complete.
	// Defaults to [DefaultHttpTimeout].
	HttpTimeout int

	// Specifies the interval between keep-alive probes for an active network connection.
	// Defaults to [DefaultHttpKeepAlive].
	HttpKeepAliveInterval int

	// The maximum amount of time an idle (keep-alive) connection will remain idle before closing itself.
	// Defaults to [DefaultIdleConnTimeout].
	IdleConnTimeout int

	// The maximum amount of time to wait for a TLS handshake.
	// Defaults to [DefaultTLSHandshakeTimeout].
	TLSHandshakeTimeout int
}

func ParseTransportConfig(data string) (*TransportConfig, error) {
	config := &TransportConfig{}

	if strings.TrimSpace(data) == "" {
		return nil, errors.New("missing transport configuration")
	}

	if err := json.Unmarshal([]byte(data), config); err != nil {
		return nil, err
	}

	return config, nil
}

// NewTransport creates a new transport using the given configuration.
func NewTransport(config *TransportConfig) (*oohttp.StdlibTransport, error) {
	dialer := &net.Dialer{
		Timeout:   DefaultHttpTimeout,
		KeepAlive: DefaultHttpKeepAlive,
	}

	if config.HttpTimeout != 0 {
		dialer.Timeout = time.Duration(config.HttpTimeout) * time.Second
	}
	if config.HttpKeepAliveInterval != 0 {
		dialer.KeepAlive = time.Duration(config.HttpKeepAliveInterval) * time.Second
	}

	tlsFactory := &internalTls.FactoryWithClientHelloId{}

	if config.HexClientHello != "" {
		spec, err := config.HexClientHello.ToClientHelloId()
		if err != nil {
			return nil, errors.Wrap(err, "create spec from client hello")
		}
		tlsFactory.ClientHelloSpec = spec
	} else if config.Fingerprint != "" {
		tlsFactory.ClientHelloID = config.Fingerprint.ToClientHelloId()
	}

	transport := &oohttp.Transport{
		Proxy:                 oohttp.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       DefaultIdleConnTimeout,
		TLSHandshakeTimeout:   DefaultTLSHandshakeTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientFactory:      tlsFactory.NewUTLSConn,
	}

	// add realistic initial HTTP2 SETTINGS to Chrome browser fingerprints
	if strings.HasPrefix(string(config.Fingerprint), "Chrome") {
		transport.EnableCustomInitialSettings()
		transport.HeaderTableSize = 4096 // 65536 // TODO: 4096 seems to be the max; modify oohtpp fork (see `http2/hpack` package) to support higher value
		transport.EnablePush = 0
		transport.MaxConcurrentStreams = 1000
		transport.InitialWindowSize = 6291456
		transport.MaxFrameSize = 16384
		transport.MaxHeaderListSize = 262144
	}

	if config.IdleConnTimeout != 0 {
		transport.IdleConnTimeout = time.Duration(config.IdleConnTimeout) * time.Second
	}
	if config.TLSHandshakeTimeout != 0 {
		transport.TLSHandshakeTimeout = time.Duration(config.TLSHandshakeTimeout) * time.Second
	}

	return &oohttp.StdlibTransport{
		Transport: transport,
	}, nil
}

// 5a14b2b27d2a8ef6ac2195f634dc9627
