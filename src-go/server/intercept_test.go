package server

import (
	"bytes"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeBurp stands in for Burp's proxy listener and records everything sent to it.
type fakeBurp struct {
	mu       sync.Mutex
	received bytes.Buffer
	conns    []net.Conn
}

func (b *fakeBurp) track(conn net.Conn) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.conns = append(b.conns, conn)
}

// closeConns ends the proxy's tunnels, which otherwise stay open waiting for Burp to hang up.
func (b *fakeBurp) closeConns() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, conn := range b.conns {
		conn.Close()
	}
}

func (b *fakeBurp) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.received.Write(p)
}

func (b *fakeBurp) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.received.String()
}

func newTestInterceptProxy(t *testing.T) (*interceptProxy, *fakeBurp) {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	burp := &fakeBurp{}
	t.Cleanup(func() {
		l.Close()
		burp.closeConns()
	})

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			burp.track(conn)
			go func() {
				defer conn.Close()
				io.Copy(burp, conn)
			}()
		}
	}()

	p, err := newInterceptProxy("127.0.0.1:0", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Stop() })
	go p.Start()

	return p, burp
}

func waitForFingerprint(t *testing.T, p *interceptProxy, want string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := p.getTLSFingerprint(); got == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	got := p.getTLSFingerprint()
	t.Fatalf("captured ClientHello of %d hex chars, want %d:\ngot  %.64s...\nwant %.64s...", len(got), len(want), got, want)
}

func TestInterceptProxyCapturesClientHello(t *testing.T) {
	hello := readClientHelloFixture(t, "chromium_154")
	p, _ := newTestInterceptProxy(t)

	conn, err := net.Dial("tcp", p.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err := io.WriteString(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(hello); err != nil {
		t.Fatal(err)
	}

	waitForFingerprint(t, p, hex.EncodeToString(hello))
}

func TestInterceptProxyCapturesFragmentedClientHello(t *testing.T) {
	hello := readClientHelloFixture(t, "firefox_158")
	p, _ := newTestInterceptProxy(t)

	conn, err := net.Dial("tcp", p.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	for _, fragment := range [][]byte{hello[:3], hello[3:5], hello[5:100], hello[100:]} {
		if _, err := conn.Write(fragment); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	waitForFingerprint(t, p, hex.EncodeToString(hello))
}

func TestInterceptProxyStop(t *testing.T) {
	p, _ := newTestInterceptProxy(t)
	addr := p.listener.Addr().String()

	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}

	if conn, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		conn.Close()
		t.Error("intercept proxy still accepts connections after Stop")
	}
}

func TestInterceptProxyIgnoresTruncatedClientHello(t *testing.T) {
	hello := readClientHelloFixture(t, "chromium_154")
	p, burp := newTestInterceptProxy(t)

	conn, err := net.Dial("tcp", p.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(hello[:100]); err != nil {
		t.Fatal(err)
	}
	conn.Close()

	time.Sleep(500 * time.Millisecond)
	if strings.Contains(burp.String(), "awesome-tls-error") {
		t.Error("client disconnecting mid-ClientHello was reported to Burp as an error")
	}
}
