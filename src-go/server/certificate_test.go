package server

import (
	"bytes"
	"crypto/x509"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// useTempConfigDir points os.UserConfigDir at a temporary directory on every platform and returns where the CA files will be written.
func useTempConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)
	t.Setenv("AppData", dir)

	configDir, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(configDir, "burp-awesome-tls")
}

func TestNewCertificateAuthority(t *testing.T) {
	dir := useTempConfigDir(t)

	ca, key, err := NewCertificateAuthority()
	if err != nil {
		t.Fatal(err)
	}

	if !ca.IsCA {
		t.Error("certificate is not a CA")
	}
	if !slices.Contains(ca.DNSNames, "localhost") {
		t.Errorf("DNSNames = %v, want localhost", ca.DNSNames)
	}
	if !key.PublicKey.Equal(ca.PublicKey) {
		t.Error("private key does not match certificate")
	}
	for _, file := range []string{caFile, caKeyFile} {
		if _, err := os.Stat(filepath.Join(dir, file)); err != nil {
			t.Errorf("%s not written: %v", file, err)
		}
	}
}

func TestNewCertificateAuthorityReusesStoredCA(t *testing.T) {
	useTempConfigDir(t)

	first, firstKey, err := NewCertificateAuthority()
	if err != nil {
		t.Fatal(err)
	}
	second, secondKey, err := NewCertificateAuthority()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(first.Raw, second.Raw) {
		t.Error("CA was regenerated instead of loaded from disk")
	}
	if !firstKey.Equal(secondKey) {
		t.Error("CA key was regenerated instead of loaded from disk")
	}
}

func TestNewCertificateAuthorityReplacesCorruptCA(t *testing.T) {
	dir := useTempConfigDir(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, caFile), []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}

	ca, _, err := NewCertificateAuthority()
	if err != nil {
		t.Fatal(err)
	}

	stored, err := os.ReadFile(filepath.Join(dir, caFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParseCertificate(stored); err != nil || !bytes.Equal(stored, ca.Raw) {
		t.Error("corrupt CA on disk was not replaced")
	}
}
