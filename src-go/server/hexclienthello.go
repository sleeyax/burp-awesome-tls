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

	for i, extension := range spec.Extensions {
		// Replace ECH extension with a GREASE ECH extension.
		// Real ECH is not supported yet.
		if genericExtension, ok := extension.(*utls.GenericExtension); ok {
			if genericExtension.Id == utls.ExtensionECH {
				spec.Extensions[i] = utls.BoringGREASEECH()
			}
		}

		// If the PSK extension already contains a key, it's identified as a 'fake PSK' extensions by utls.
		// So we replace it with a real PSK extension.
		if _, ok := extension.(*utls.FakePreSharedKeyExtension); ok {
			spec.Extensions[i] = &utls.UtlsPreSharedKeyExtension{}
		}
	}

	return *spec, nil
}
