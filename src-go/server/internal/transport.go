package internal

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bogdanfinn/fhttp/http2"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	utls "github.com/bogdanfinn/utls"
	"strings"
	"time"
)

const DefaultHttpTimeout = time.Duration(30) * time.Second

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
	Fingerprint string

	// Hexadecimal Client Hello to use
	HexClientHello HexClientHello

	// The maximum amount of time a dial will wait for a connect to complete.
	// Defaults to [DefaultHttpTimeout].
	HttpTimeout int

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

func NewClient() (tls_client.HttpClient, error) {
	config := DefaultConfig

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
