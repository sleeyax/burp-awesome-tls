package internal

import (
	"encoding/json"
	"errors"
	"net"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"

	internalTls "server/internal/tls"

	oohttp "github.com/ooni/oohttp"
)

const (
	DefaultHttpTimeout         = time.Duration(30) * time.Second
	DefaultHttpKeepAlive       = time.Duration(30) * time.Second
	DefaultIdleConnTimeout     = time.Duration(90) * time.Second
	DefaultTLSHandshakeTimeout = time.Duration(10) * time.Second
)

var DefaultConfig TransportConfig

type RequestConfig struct {
	Host   string
	Scheme string
}

type TransportConfig struct {
	// InterceptProxyAddr to intercept client tls fingerprint
	InterceptProxyAddr string

	// BurpAddr
	BurpAddr string

	// The TLS fingerprint to use.
	Fingerprint internalTls.Fingerprint

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

	// UseInterceptedFingerprint use intercepted fingerprint
	UseInterceptedFingerprint bool
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

func ParseRequestConfig(data string) (*RequestConfig, error) {
	config := &RequestConfig{}

	if strings.TrimSpace(data) == "" {
		return nil, errors.New("missing request configuration")
	}

	if err := json.Unmarshal([]byte(data), config); err != nil {
		return nil, err
	}

	return config, nil
}

// NewTransport creates a new transport using the given configuration.
func NewTransport(getInterceptedFingerprint func(sni string) string) (*oohttp.StdlibTransport, error) {
	dialer := &net.Dialer{
		Timeout:   DefaultHttpTimeout,
		KeepAlive: DefaultHttpKeepAlive,
	}

	config := DefaultConfig

	if config.HttpTimeout != 0 {
		dialer.Timeout = time.Duration(config.HttpTimeout) * time.Second
	}
	if config.HttpKeepAliveInterval != 0 {
		dialer.KeepAlive = time.Duration(config.HttpKeepAliveInterval) * time.Second
	}

	var spec *utls.ClientHelloSpec
	clientHelloID := config.Fingerprint.ToClientHelloId()

	getClientHello := func(sni string) (*utls.ClientHelloID, *utls.ClientHelloSpec) {
		if !config.UseInterceptedFingerprint {
			return clientHelloID, spec
		}

		interceptedFingerprint := getInterceptedFingerprint(sni)

		if interceptedFingerprint == "" {
			return clientHelloID, spec
		}

		interceptedSpec, err := internalTls.HexClientHello(interceptedFingerprint).ToClientHelloSpec()
		if err == nil {
			return &utls.HelloCustom, interceptedSpec
		}

		return clientHelloID, spec
	}

	tlsFactory := &internalTls.FactoryWithClientHelloId{GetClientHello: getClientHello}

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
