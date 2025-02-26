package server

import (
	"encoding/hex"
	"errors"
	utls "github.com/bogdanfinn/utls"
)

type HexClientHello string

func (hexClientHello HexClientHello) ToClientHelloSpec() (utls.ClientHelloSpec, error) {
	if hexClientHello == "" {
		return utls.ClientHelloSpec{}, errors.New("empty client hello")
	}

	raw, err := hex.DecodeString(string(hexClientHello))
	if err != nil {
		return utls.ClientHelloSpec{}, err
	}

	fingerprinter := &utls.Fingerprinter{
		AllowBluntMimicry: true,
	}
	spec, err := fingerprinter.RawClientHello(raw)
	if err != nil {
		return utls.ClientHelloSpec{}, err
	}

	return *spec, nil
}
