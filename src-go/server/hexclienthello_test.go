package server

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"slices"
	"strings"
	"testing"

	utls "github.com/bogdanfinn/utls"
)

// Fixtures are ClientHellos captured from real browsers connecting to a local listener.
var clientHelloFixtures = []string{"chromium_154", "firefox_158"}

func readClientHelloFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name + ".hex")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// withExtension appends an extension to a ClientHello record, fixing up the record, handshake and extensions lengths.
func withExtension(t *testing.T, record []byte, id uint16, data []byte) []byte {
	t.Helper()

	r := &byteReader{t: t, b: record}
	r.skip(5 + 4 + 2 + 32)
	r.skip(int(r.uint8()))
	r.skip(int(r.uint16()))
	r.skip(int(r.uint8()))
	extensionsLengthOffset := len(record) - len(r.b)

	extension := binary.BigEndian.AppendUint16(nil, id)
	extension = binary.BigEndian.AppendUint16(extension, uint16(len(data)))
	extension = append(extension, data...)
	n := len(extension)

	out := append(slices.Clone(record), extension...)
	binary.BigEndian.PutUint16(out[3:], binary.BigEndian.Uint16(out[3:])+uint16(n))
	handshakeLength := uint32(out[6])<<16 | uint32(out[7])<<8 | uint32(out[8]) + uint32(n)
	out[6], out[7], out[8] = byte(handshakeLength>>16), byte(handshakeLength>>8), byte(handshakeLength)
	binary.BigEndian.PutUint16(out[extensionsLengthOffset:], binary.BigEndian.Uint16(out[extensionsLengthOffset:])+uint16(n))
	return out
}

func TestToClientHelloSpecKeepsCipherSuites(t *testing.T) {
	for _, name := range clientHelloFixtures {
		t.Run(name, func(t *testing.T) {
			raw := readClientHelloFixture(t, name)

			spec, err := HexClientHello(hex.EncodeToString(raw)).ToClientHelloSpec()
			if err != nil {
				t.Fatal(err)
			}

			got := slices.DeleteFunc(slices.Clone(spec.CipherSuites), isGREASE)
			if want := parseHelloShape(t, raw).cipherSuites; !slices.Equal(got, want) {
				t.Errorf("cipher suites = %04x, want %04x", got, want)
			}
			if len(spec.Extensions) == 0 {
				t.Error("spec has no extensions")
			}
		})
	}
}

func TestToClientHelloSpecUsesGREASEECH(t *testing.T) {
	for _, name := range clientHelloFixtures {
		t.Run(name, func(t *testing.T) {
			raw := readClientHelloFixture(t, name)
			if !slices.Contains(parseHelloShape(t, raw).extensions, utls.ExtensionECH) {
				t.Skip("fixture has no ECH extension")
			}

			spec, err := HexClientHello(hex.EncodeToString(raw)).ToClientHelloSpec()
			if err != nil {
				t.Fatal(err)
			}

			var foundGREASEECH bool
			for _, extension := range spec.Extensions {
				switch e := extension.(type) {
				case *utls.GREASEEncryptedClientHelloExtension:
					foundGREASEECH = true
				case *utls.GenericExtension:
					if e.Id == utls.ExtensionECH {
						t.Error("ECH extension left as a generic extension")
					}
				}
			}
			if !foundGREASEECH {
				t.Error("no GREASE ECH extension in spec")
			}
		})
	}
}

func TestToClientHelloSpecReplacesFakePSK(t *testing.T) {
	identities := []byte{0x00, 0x0c, 0x00, 0x06, 't', 'i', 'c', 'k', 'e', 't', 0x00, 0x00, 0x00, 0x00}
	binders := append([]byte{0x00, 0x21, 0x20}, make([]byte, 32)...)
	raw := withExtension(t, readClientHelloFixture(t, "chromium_154"), 41, append(identities, binders...))

	spec, err := HexClientHello(hex.EncodeToString(raw)).ToClientHelloSpec()
	if err != nil {
		t.Fatal(err)
	}

	var foundPSK bool
	for _, extension := range spec.Extensions {
		switch extension.(type) {
		case *utls.FakePreSharedKeyExtension:
			t.Error("fake PSK extension left in spec")
		case *utls.UtlsPreSharedKeyExtension:
			foundPSK = true
		}
	}
	if !foundPSK {
		t.Error("no PSK extension in spec")
	}
}

func TestToClientHelloSpecRejectsInvalidInput(t *testing.T) {
	chromium := hex.EncodeToString(readClientHelloFixture(t, "chromium_154"))

	tests := map[string]HexClientHello{
		"empty":        "",
		"not hex":      "zz",
		"odd length":   "160",
		"truncated":    HexClientHello(chromium[:40]),
		"wrong record": HexClientHello("17" + chromium[2:]),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := input.ToClientHelloSpec(); err == nil {
				t.Error("expected an error")
			}
		})
	}
}
