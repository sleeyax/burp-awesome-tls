package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"sync/atomic"
	"time"
)

// Based on: https://github.com/ulixee/hero/blob/main/mitm-socket/go/generate_cert.go

var caFile string = "ca.der"
var caKeyFile string = "caKey.der"

// While generating a new certificate, in order to get a unique serial
// number every time we increment this value.
var currentSerialNumber int64 = time.Now().Unix()

func readCertFromDisk(file string) (*x509.Certificate, error) {
	bytes, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func readPrivateKeyFromDisk(file string) (*rsa.PrivateKey, error) {
	bytes, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	key, err := x509.ParsePKCS8PrivateKey(bytes)
	if err != nil {
		return nil, err
	}

	privatePkcs8RsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("Pkcs8 contained non-RSA key. Expected RSA key.")
	}

	return privatePkcs8RsaKey, nil
}

// NewCertificateAuthority creates a new CA certificate and associated private key, unless it already exists on disk.
func NewCertificateAuthority() (*x509.Certificate, *rsa.PrivateKey, error) {
	certFromDisk, err := readCertFromDisk(caFile)

	if err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("Error reading cert from disk", caFile, err)
	} else if err == nil {
		keyFromDisk, err := readPrivateKeyFromDisk(caKeyFile)
		if err != nil {
			log.Printf("Error reading private key from disk", caKeyFile, err)
		} else {
			return certFromDisk, keyFromDisk, nil
		}
	}

	// Generating the private key that will be used for domain certificates
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	pub := priv.Public()

	// Subject Key Identifier support for end entity certificate.
	// https://tools.ietf.org/html/rfc3280#section-4.2.1.2
	pkixpub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	h := sha1.New()
	_, err = h.Write(pkixpub)
	if err != nil {
		return nil, nil, err
	}
	keyID := h.Sum(nil)

	// Increment the serial number
	serial := atomic.AddInt64(&currentSerialNumber, 1)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName:   "Awesome TLS",
			Organization: []string{"Sleeyax"},
		},
		SubjectKeyId:          keyID,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		NotBefore:             time.Now().AddDate(-1, 0, 0),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		DNSNames:              []string{"awesometls", "localhost"},
		IsCA:                  true,
	}

	raw, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, nil, err
	}

	err = os.WriteFile(caFile, raw, 0600)
	if err != nil {
		return nil, nil, err
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}

	err = os.WriteFile(caKeyFile, privBytes, 0600)
	if err != nil {
		return nil, nil, err
	}

	// Parse certificate bytes so that we have a leaf certificate.
	x509c, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, nil, err
	}

	return x509c, priv, nil
}
