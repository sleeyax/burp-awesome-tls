package tls

import (
	"encoding/hex"
	"errors"
	"fmt"

	utls "github.com/refraction-networking/utls"
)

type HexClientHello string

func (hexClientHello HexClientHello) ToClientHelloSpec() (*utls.ClientHelloSpec, error) {
	if hexClientHello == "" {
		return nil, errors.New("empty client hello")
	}

	raw, err := hex.DecodeString(string(hexClientHello))
	if err != nil {
		return nil, fmt.Errorf("decode hexClientHello: %w", err)
	}

	fingerprinter := &utls.Fingerprinter{}
	spec, err := fingerprinter.RawClientHello(raw)
	if err != nil {
		return nil, fmt.Errorf("FingerprintClientHello: %w", err)
	}

	return spec, nil
}
