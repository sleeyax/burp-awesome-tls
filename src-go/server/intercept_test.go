package server

import (
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"
)

func newTestInterceptProxy(t *testing.T) *interceptProxy {
	t.Helper()

	burp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { burp.Close() })
	go func() {
		for {
			conn, err := burp.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(io.Discard, conn)
			}()
		}
	}()

	p, err := newInterceptProxy("127.0.0.1:0", burp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Stop() })
	go p.Start()

	return p
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
	p := newTestInterceptProxy(t)

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
	p := newTestInterceptProxy(t)

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
	p := newTestInterceptProxy(t)
	addr := p.listener.Addr().String()

	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}

	if conn, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		conn.Close()
		t.Error("intercept proxy still accepts connections after Stop")
	}
}
