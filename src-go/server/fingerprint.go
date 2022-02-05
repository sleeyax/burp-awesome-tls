package server

import utls "github.com/refraction-networking/utls"

// Fingerprint represents a TLS fingerprint.
type Fingerprint string

const (
	Chrome83 Fingerprint = "CHROME_83"
)

func (f Fingerprint) ToSpec() *utls.ClientHelloSpec {
	// TODO: add more custom fingerprints
	switch f {
	case Chrome83:
		return &utls.ClientHelloSpec{
			CipherSuites: []uint16{
				utls.GREASE_PLACEHOLDER,
				utls.TLS_AES_128_GCM_SHA256,
				utls.TLS_AES_256_GCM_SHA384,
				utls.TLS_CHACHA20_POLY1305_SHA256,
				utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_RSA_WITH_AES_128_CBC_SHA,
				utls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: []utls.TLSExtension{
				&utls.UtlsGREASEExtension{},
				&utls.SNIExtension{},
				&utls.UtlsExtendedMasterSecretExtension{},
				&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
				&utls.SupportedCurvesExtension{[]utls.CurveID{
					utls.CurveID(utls.GREASE_PLACEHOLDER),
					utls.X25519,
					utls.CurveP256,
					utls.CurveP384,
				}},
				&utls.SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&utls.SessionTicketExtension{},
				&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&utls.StatusRequestExtension{},
				&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
					utls.ECDSAWithP256AndSHA256,
					utls.PSSWithSHA256,
					utls.PKCS1WithSHA256,
					utls.ECDSAWithP384AndSHA384,
					utls.PSSWithSHA384,
					utls.PKCS1WithSHA384,
					utls.PSSWithSHA512,
					utls.PKCS1WithSHA512,
				}},
				&utls.SCTExtension{},
				&utls.KeyShareExtension{[]utls.KeyShare{
					{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: utls.X25519},
				}},
				&utls.PSKKeyExchangeModesExtension{[]uint8{
					utls.PskModeDHE,
				}},
				&utls.SupportedVersionsExtension{[]uint16{
					utls.GREASE_PLACEHOLDER,
					utls.VersionTLS13,
					utls.VersionTLS12,
					utls.VersionTLS11,
					utls.VersionTLS10,
				}},
				&utls.UtlsCompressCertExtension{[]utls.CertCompressionAlgo{
					utls.CertCompressionBrotli,
				}},
				&utls.UtlsGREASEExtension{},
				&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
			},
		}
	default:
		return Chrome83.ToSpec()
	}
}
