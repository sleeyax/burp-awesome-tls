package server

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"slices"
	"testing"

	fhttp "github.com/bogdanfinn/fhttp"
)

func TestParseTransportConfig(t *testing.T) {
	config, err := ParseTransportConfig(`{
		"Host": "example.com",
		"Scheme": "https",
		"Fingerprint": "chrome_133",
		"HttpTimeout": 15,
		"UseInterceptedFingerprint": true,
		"HeaderOrder": ["Host", "User-Agent"],
		"ExternalProxyUrl": "http://user:pass@proxy:8080"
	}`)
	if err != nil {
		t.Fatal(err)
	}

	if config.Host != "example.com" || config.Scheme != "https" || config.Fingerprint != "chrome_133" || config.HttpTimeout != 15 || !config.UseInterceptedFingerprint || config.ExternalProxyUrl != "http://user:pass@proxy:8080" {
		t.Errorf("unexpected config: %+v", config)
	}
	if !slices.Equal(config.HeaderOrder, []string{"Host", "User-Agent"}) {
		t.Errorf("HeaderOrder = %v", config.HeaderOrder)
	}
}

func TestParseTransportConfigRejectsInvalidInput(t *testing.T) {
	for name, input := range map[string]string{
		"empty":      "",
		"whitespace": "  \t",
		"malformed":  "{",
		"wrong type": `{"HttpTimeout": "30"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseTransportConfig(input); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestNewClientFingerprints(t *testing.T) {
	for _, fingerprint := range []string{"", "default", "Default", "chrome_133"} {
		if _, err := NewClient(&TransportConfig{Fingerprint: fingerprint}); err != nil {
			t.Errorf("%q: %v", fingerprint, err)
		}
	}

	if _, err := NewClient(&TransportConfig{Fingerprint: "netscape_4"}); err == nil {
		t.Error("expected an error for an unknown fingerprint")
	}
}

func TestNewClientPrefersHexClientHelloOverFingerprint(t *testing.T) {
	_, err := NewClient(&TransportConfig{Fingerprint: "chrome_133", HexClientHello: "not hex"})
	if err == nil {
		t.Error("expected the invalid hex ClientHello to be used and rejected")
	}
}

func TestNewClientUsesExternalProxy(t *testing.T) {
	target := newTargetServer(t, okResponse)
	proxyAddr, connects := newConnectProxy(t)

	client, err := NewClient(&TransportConfig{ExternalProxyUrl: "http://" + proxyAddr, HttpTimeout: 10})
	if err != nil {
		t.Fatal(err)
	}

	req, err := fhttp.NewRequest(http.MethodGet, "https://"+target.addr+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	target.nextRequest(t)

	select {
	case got := <-connects:
		if got != target.addr {
			t.Errorf("proxy tunnelled to %q, want %q", got, target.addr)
		}
	default:
		t.Error("request did not go through the external proxy")
	}
}

// newConnectProxy starts an HTTP CONNECT proxy and reports each tunnel's destination.
func newConnectProxy(t *testing.T) (string, <-chan string) {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })

	connects := make(chan string, 16)
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()

				r := bufio.NewReader(conn)
				req, err := http.ReadRequest(r)
				if err != nil || req.Method != http.MethodConnect {
					return
				}
				connects <- req.Host

				upstream, err := net.Dial("tcp", req.Host)
				if err != nil {
					return
				}
				defer upstream.Close()

				if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
					return
				}
				go io.Copy(upstream, r)
				io.Copy(conn, upstream)
			}()
		}
	}()

	return l.Addr().String(), connects
}
