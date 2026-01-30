package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	utls "github.com/bogdanfinn/utls"
)

type TransportConfig struct {
	// Hostname.
	Host string

	// Protocol scheme (HTTP or HTTPS).
	Scheme string

	// InterceptProxyAddr to intercept client tls fingerprint
	InterceptProxyAddr string

	// BurpAddr
	BurpAddr string

	// The TLS fingerprint to use.
	Fingerprint string

	// Hexadecimal Client Hello to use
	HexClientHello HexClientHello

	// The maximum amount of time a dial will wait for a connect to complete.
	// Defaults to [DefaultHttpTimeout].
	HttpTimeout int

	// UseInterceptedFingerprint use intercepted fingerprint
	UseInterceptedFingerprint bool

	// HeaderOrder is the order of headers to be sent in the request.
	HeaderOrder []string

	// ExternalProxyUrl is an optional upstream proxy (format: `http://user:pass@host:port`).
	ExternalProxyUrl string
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

func NewClient(config *TransportConfig) (tls_client.HttpClient, error) {
	options := []tls_client.HttpClientOption{
		tls_client.WithNotFollowRedirects(),
		tls_client.WithInsecureSkipVerify(),
	}

	if config.HttpTimeout != 0 {
		options = append(options, tls_client.WithTimeoutSeconds(config.HttpTimeout))
	}

	if config.ExternalProxyUrl != "" {
		options = append(options, tls_client.WithProxyUrl(config.ExternalProxyUrl))
	}

	// The order of precedence is:
	// 1. Custom client hello from intercept proxy
	// 2. Custom client hello from hex string
	// 3. Preconfigured fingerprint
	if config.HexClientHello != "" {
		customClientHelloSpec, err := config.HexClientHello.ToClientHelloSpec()
		if err != nil {
			return nil, err
		}

		customClientHelloID := utls.ClientHelloID{
			Client:  "CustomFromHex",
			Version: "1",
			SpecFactory: func() (utls.ClientHelloSpec, error) {
				return customClientHelloSpec, nil
			},
		}

		defaultProfile := profiles.DefaultClientProfile
		customClientProfile := profiles.NewClientProfile(
			customClientHelloID,
			defaultProfile.GetSettings(),
			defaultProfile.GetSettingsOrder(),
			defaultProfile.GetPseudoHeaderOrder(),
			defaultProfile.GetConnectionFlow(),
			defaultProfile.GetPriorities(),
			defaultProfile.GetHeaderPriority(),
			defaultProfile.GetStreamID(),
			defaultProfile.GetAllowHTTP(),
		)

		options = append(options, tls_client.WithClientProfile(customClientProfile))
	} else if config.Fingerprint != "" {
		var clientProfile profiles.ClientProfile
		if strings.ToLower(config.Fingerprint) == "default" {
			clientProfile = profiles.DefaultClientProfile
		} else {
			var ok bool
			if clientProfile, ok = profiles.MappedTLSClients[config.Fingerprint]; !ok {
				return nil, fmt.Errorf("failed to create client profile for unrecognized fingerprint '%s'", config.Fingerprint)
			}
		}

		options = append(options, tls_client.WithClientProfile(clientProfile))
	}

	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	if err != nil {
		return nil, err
	}

	return client, nil
}
