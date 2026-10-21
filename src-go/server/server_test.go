package server

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/bogdanfinn/fhttp/httptest"
	"github.com/bogdanfinn/tls-client/profiles"
	utls "github.com/bogdanfinn/utls"
)

const okResponse = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"

type spoofRequest struct {
	method  string
	path    string
	headers [][2]string
	body    string
	config  TransportConfig
}

func newSpoofServer(t *testing.T) string {
	t.Helper()
	s := httptest.NewServer(newHandler())
	t.Cleanup(s.Close)
	return s.URL
}

// configFor returns the config Burp would send for a request to the target.
func configFor(target *targetServer) TransportConfig {
	return TransportConfig{
		Host:        target.addr,
		Scheme:      "https",
		Fingerprint: "default",
		HttpTimeout: 10,
	}
}

func spoof(t *testing.T, spoofURL string, r spoofRequest) (*http.Response, string) {
	t.Helper()

	req, err := http.NewRequest(cmpOr(r.method, http.MethodGet), spoofURL+cmpOr(r.path, "/"), strings.NewReader(r.body))
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range r.headers {
		req.Header.Add(h[0], h[1])
	}
	config, err := json.Marshal(r.config)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(ConfigurationHeaderKey, string(config))

	client := &http.Client{
		Transport:     &http.Transport{DisableCompression: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res, string(body)
}

func cmpOr(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// directClientHello captures the ClientHello utls produces for a profile when dialled directly, which is what the spoof server should reproduce.
func directClientHello(t *testing.T, target *targetServer, profile profiles.ClientProfile) []byte {
	t.Helper()

	conn, err := net.Dial("tcp", target.addr)
	if err != nil {
		t.Fatal(err)
	}
	host, _, _ := net.SplitHostPort(target.addr)
	config := &utls.Config{ServerName: host, InsecureSkipVerify: true, OmitEmptyPsk: true}
	uconn := utls.UClient(conn, config, profile.GetClientHelloId(), false, false, false)
	_ = uconn.Handshake()
	uconn.Close()

	return target.nextRequest(t).clientHello
}

func assertSameShape(t *testing.T, want, got []byte) {
	t.Helper()
	wantShape, gotShape := parseHelloShape(t, want), parseHelloShape(t, got)
	if !slices.Equal(wantShape.cipherSuites, gotShape.cipherSuites) {
		t.Errorf("cipher suites differ:\nwant %04x\ngot  %04x", wantShape.cipherSuites, gotShape.cipherSuites)
	}
	if !slices.Equal(wantShape.extensions, gotShape.extensions) {
		t.Errorf("extensions differ:\nwant %d\ngot  %d", wantShape.extensions, gotShape.extensions)
	}
}

func TestFingerprintIsApplied(t *testing.T) {
	for _, name := range []string{"chrome_133", "firefox_135", "safari_ios_18_0"} {
		t.Run(name, func(t *testing.T) {
			target := newTargetServer(t, okResponse)
			spoofURL := newSpoofServer(t)

			config := configFor(target)
			config.Fingerprint = name
			res, body := spoof(t, spoofURL, spoofRequest{config: config})
			if res.StatusCode != http.StatusOK {
				t.Fatalf("status %d: %s", res.StatusCode, body)
			}
			got := target.nextRequest(t).clientHello

			assertSameShape(t, directClientHello(t, target, profiles.MappedTLSClients[name]), got)
		})
	}
}

func TestDistinctFingerprintsProduceDistinctClientHellos(t *testing.T) {
	target := newTargetServer(t, okResponse)
	spoofURL := newSpoofServer(t)

	shapes := map[string]helloShape{}
	for _, name := range []string{"chrome_133", "firefox_135"} {
		config := configFor(target)
		config.Fingerprint = name
		spoof(t, spoofURL, spoofRequest{config: config})
		shapes[name] = parseHelloShape(t, target.nextRequest(t).clientHello)
	}

	if slices.Equal(shapes["chrome_133"].cipherSuites, shapes["firefox_135"].cipherSuites) {
		t.Error("chrome and firefox fingerprints sent identical cipher suites")
	}
}

func TestHexClientHelloRoundTrip(t *testing.T) {
	target := newTargetServer(t, okResponse)
	spoofURL := newSpoofServer(t)

	want := directClientHello(t, target, profiles.MappedTLSClients["firefox_135"])

	config := configFor(target)
	config.Fingerprint = "chrome_133"
	config.HexClientHello = HexClientHello(hex.EncodeToString(want))
	res, body := spoof(t, spoofURL, spoofRequest{config: config})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", res.StatusCode, body)
	}

	assertSameShape(t, want, target.nextRequest(t).clientHello)
}

func TestEveryFingerprintCompletesARequest(t *testing.T) {
	target := newTargetServer(t, okResponse)
	spoofURL := newSpoofServer(t)

	for _, name := range GetFingerprints() {
		t.Run(name, func(t *testing.T) {
			config := configFor(target)
			config.Fingerprint = name
			res, body := spoof(t, spoofURL, spoofRequest{config: config})
			target.nextRequest(t)
			if res.StatusCode != http.StatusOK || body != "ok" {
				t.Errorf("status %d: %s", res.StatusCode, body)
			}
		})
	}
}

func TestRequestIsForwarded(t *testing.T) {
	target := newTargetServer(t, okResponse)
	spoofURL := newSpoofServer(t)

	config := configFor(target)
	config.HeaderOrder = []string{"X-Second", "User-Agent", "X-First", "Content-Type"}
	res, body := spoof(t, spoofURL, spoofRequest{
		method: http.MethodPost,
		path:   "/submit?q=1",
		headers: [][2]string{
			{"X-First", "1"},
			{"Content-Type", "application/json"},
			{"X-Second", "2"},
			{"User-Agent", "burp"},
		},
		body:   `{"hello":"world"}`,
		config: config,
	})
	if res.StatusCode != http.StatusOK || body != "ok" {
		t.Fatalf("status %d: %s", res.StatusCode, body)
	}

	got := target.nextRequest(t)
	if got.requestLine != "POST /submit?q=1 HTTP/1.1" {
		t.Errorf("request line = %q", got.requestLine)
	}
	if string(got.body) != `{"hello":"world"}` {
		t.Errorf("body = %q", got.body)
	}
	if v := got.header(ConfigurationHeaderKey); v != "" {
		t.Errorf("configuration header leaked to target: %q", v)
	}

	var ordered []string
	for _, name := range got.headerNames() {
		if slices.ContainsFunc(config.HeaderOrder, func(h string) bool { return strings.EqualFold(h, name) }) {
			ordered = append(ordered, strings.ToLower(name))
		}
	}
	want := []string{"x-second", "user-agent", "x-first", "content-type"}
	if !slices.Equal(ordered, want) {
		t.Errorf("header order = %v, want %v (all headers: %v)", ordered, want, got.headerNames())
	}
}

func TestRedirectIsNotFollowed(t *testing.T) {
	target := newTargetServer(t, "HTTP/1.1 302 Found\r\nLocation: /elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	spoofURL := newSpoofServer(t)

	res, _ := spoof(t, spoofURL, spoofRequest{config: configFor(target)})
	target.nextRequest(t)

	if res.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want %d", res.StatusCode, http.StatusFound)
	}
	if loc := res.Header.Get("Location"); loc != "/elsewhere" {
		t.Errorf("Location = %q", loc)
	}
	select {
	case <-target.captured:
		t.Error("redirect was followed")
	default:
	}
}

func TestCompressedResponseIsDecodedWithMatchingContentLength(t *testing.T) {
	const plain = "hello, decompressed world"
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	zw.Write([]byte(plain))
	zw.Close()

	response := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", compressed.Len(), compressed.String())
	target := newTargetServer(t, response)
	spoofURL := newSpoofServer(t)

	res, body := spoof(t, spoofURL, spoofRequest{
		headers: [][2]string{{"Accept-Encoding", "gzip"}},
		config:  configFor(target),
	})
	target.nextRequest(t)

	if body != plain {
		t.Errorf("body = %q, want %q", body, plain)
	}
	if res.ContentLength != int64(len(plain)) {
		t.Errorf("Content-Length = %d, want %d", res.ContentLength, len(plain))
	}
	if ce := res.Header.Get("Content-Encoding"); ce != "" {
		t.Errorf("Content-Encoding = %q on a decoded body", ce)
	}
}

func TestInvalidConfigurationReturnsError(t *testing.T) {
	spoofURL := newSpoofServer(t)

	tests := map[string]string{
		"missing":             "",
		"malformed":           "{not json",
		"unknown fingerprint": `{"Host":"127.0.0.1:1","Scheme":"https","Fingerprint":"netscape_4"}`,
		"invalid hex":         `{"Host":"127.0.0.1:1","Scheme":"https","HexClientHello":"zz"}`,
	}
	for name, header := range tests {
		t.Run(name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, spoofURL, nil)
			if header != "" {
				req.Header.Set(ConfigurationHeaderKey, header)
			}
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			body, _ := io.ReadAll(res.Body)

			if res.StatusCode != http.StatusInternalServerError || !strings.HasPrefix(string(body), "Awesome TLS error:") {
				t.Errorf("status %d: %s", res.StatusCode, body)
			}
		})
	}
}
