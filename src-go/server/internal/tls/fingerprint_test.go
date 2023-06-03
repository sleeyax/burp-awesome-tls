package tls

import "testing"

func TestFingerprint_ToClientHelloId(t *testing.T) {
	clientHelloId := Fingerprint("Chrome 100").ToClientHelloId()
	if clientHelloId.Client != "Chrome" || clientHelloId.Version != "100" {
		t.FailNow()
	}
}
