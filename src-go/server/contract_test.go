package server

import (
	"encoding/json"
	"maps"
	"os"
	"reflect"
	"slices"
	"testing"
)

// testdata/transport_config.json is also asserted on by the Java extension's TransportConfigContractTest, so both sides agree on the configuration header format.
func TestTransportConfigContract(t *testing.T) {
	data, err := os.ReadFile("testdata/transport_config.json")
	if err != nil {
		t.Fatal(err)
	}

	var keys map[string]any
	if err := json.Unmarshal(data, &keys); err != nil {
		t.Fatal(err)
	}
	var fields []string
	configType := reflect.TypeFor[TransportConfig]()
	for i := range configType.NumField() {
		fields = append(fields, configType.Field(i).Name)
	}
	if got, want := slices.Sorted(maps.Keys(keys)), slices.Sorted(slices.Values(fields)); !slices.Equal(got, want) {
		t.Errorf("contract keys = %v, TransportConfig fields = %v", got, want)
	}

	config, err := ParseTransportConfig(string(data))
	if err != nil {
		t.Fatal(err)
	}
	want := &TransportConfig{
		Host:                      "example.com:8443",
		Scheme:                    "https",
		InterceptProxyAddr:        "127.0.0.1:8886",
		BurpAddr:                  "127.0.0.1:8080",
		Fingerprint:               "chrome_133",
		HexClientHello:            "1603",
		UseInterceptedFingerprint: true,
		HttpTimeout:               30,
		HeaderOrder:               []string{"Host", "User-Agent"},
		ExternalProxyUrl:          "http://user:pass@proxy:3128",
	}
	if !reflect.DeepEqual(config, want) {
		t.Errorf("parsed %+v, want %+v", config, want)
	}
}
