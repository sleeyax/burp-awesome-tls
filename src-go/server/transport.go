package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bogdanfinn/fhttp/http2"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	utls "github.com/bogdanfinn/utls"
	"strings"
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

	if config.Fingerprint != "" {
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

	if config.HexClientHello != "" {
		customClientHelloID := utls.ClientHelloID{
			Client:  "Custom",
			Version: "1",
			SpecFactory: func() (utls.ClientHelloSpec, error) {
				return config.HexClientHello.ToClientHelloSpec()
			},
		}

		customClientProfile := profiles.NewClientProfile(
			customClientHelloID,
			make(map[http2.SettingID]uint32),
			make([]http2.SettingID, 0),
			make([]string, 0),
			0,
			make([]http2.Priority, 0),
			nil,
		)

		options = append(options, tls_client.WithClientProfile(customClientProfile))
	}

	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	if err != nil {
		return nil, err
	}

	return client, nil
}
