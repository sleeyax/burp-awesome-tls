package server

import (
	"encoding/json"
	"testing"
)

func TestNewRoundTripperFromJson(t *testing.T) {
	expected := RoundTripper{TlsFingerprint: Chrome83}
	expectedData, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}

	actual, err := NewRoundTripperFromJson(string(expectedData))
	if err != nil {
		t.Fatal(err)
	}

	if actual.TlsFingerprint != expected.TlsFingerprint {
		t.Fatalf("actual fields don't match expected!")
	}

	_, err = NewRoundTripperFromJson("")
	if err != nil {
		t.Fatal(err)
	}

	_, err = NewRoundTripperFromJson("{}")
	if err != nil {
		t.Fatal(err)
	}
}
