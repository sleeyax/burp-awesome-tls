package server

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// capturedRequest is what a targetServer saw on a single connection.
type capturedRequest struct {
	clientHello []byte
	requestLine string
	headers     [][2]string
	body        []byte
}

func (c *capturedRequest) headerNames() []string {
	names := make([]string, len(c.headers))
	for i, h := range c.headers {
		names[i] = h[0]
	}
	return names
}

func (c *capturedRequest) header(name string) string {
	for _, h := range c.headers {
		if strings.EqualFold(h[0], name) {
			return h[1]
		}
	}
	return ""
}

// targetServer is a TLS origin speaking raw HTTP/1.1, so tests can assert on the ClientHello bytes and the header order that actually went over the wire.
type targetServer struct {
	addr     string
	response string
	captured chan *capturedRequest
}

func newTargetServer(t *testing.T, response string) *targetServer {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })

	ts := &targetServer{
		addr:     l.Addr().String(),
		response: response,
		captured: make(chan *capturedRequest, 16),
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{selfSignedCertificate(t)},
		NextProtos:   []string{"http/1.1"},
	}

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go ts.handle(conn, config)
		}
	}()

	return ts
}

func (ts *targetServer) handle(conn net.Conn, config *tls.Config) {
	defer conn.Close()

	captured := &capturedRequest{}
	defer func() { ts.captured <- captured }()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	record, err := readTLSRecord(conn)
	if err != nil {
		return
	}
	captured.clientHello = record

	tlsConn := tls.Server(&prefixedConn{Conn: conn, r: io.MultiReader(bytes.NewReader(record), conn)}, config)
	if err := tlsConn.Handshake(); err != nil {
		return
	}

	r := bufio.NewReader(tlsConn)
	if captured.requestLine, err = readLine(r); err != nil {
		return
	}
	for {
		line, err := readLine(r)
		if err != nil || line == "" {
			break
		}
		name, value, _ := strings.Cut(line, ":")
		captured.headers = append(captured.headers, [2]string{name, strings.TrimSpace(value)})
	}
	if n, err := strconv.Atoi(captured.header("Content-Length")); err == nil {
		captured.body = make([]byte, n)
		if _, err := io.ReadFull(r, captured.body); err != nil {
			return
		}
	}

	_, _ = io.WriteString(tlsConn, ts.response)
}

// nextRequest returns the next connection the target saw, failing the test if none arrives.
func (ts *targetServer) nextRequest(t *testing.T) *capturedRequest {
	t.Helper()
	select {
	case c := <-ts.captured:
		return c
	case <-time.After(10 * time.Second):
		t.Fatal("target server received no connection")
		return nil
	}
}

type prefixedConn struct {
	net.Conn
	r io.Reader
}

func (c *prefixedConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

func readTLSRecord(r io.Reader) ([]byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	body := make([]byte, binary.BigEndian.Uint16(header[3:]))
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return append(header, body...), nil
}

func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}

func selfSignedCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// helloShape is the part of a ClientHello that identifies a fingerprint, with GREASE values removed and extensions sorted so randomised GREASE and extension shuffling don't cause mismatches.
type helloShape struct {
	cipherSuites []uint16
	extensions   []uint16
}

func parseHelloShape(t *testing.T, record []byte) helloShape {
	t.Helper()

	r := &byteReader{t: t, b: record}
	r.skip(5 + 4 + 2 + 32) // record header, handshake header, legacy version, random
	r.skip(int(r.uint8()))  // session id

	var shape helloShape
	cipherSuites := r.sub(int(r.uint16()))
	for len(cipherSuites.b) > 0 {
		if cs := cipherSuites.uint16(); !isGREASE(cs) {
			shape.cipherSuites = append(shape.cipherSuites, cs)
		}
	}

	r.skip(int(r.uint8())) // compression methods

	extensions := r.sub(int(r.uint16()))
	for len(extensions.b) > 0 {
		id := extensions.uint16()
		extensions.skip(int(extensions.uint16()))
		if !isGREASE(id) {
			shape.extensions = append(shape.extensions, id)
		}
	}
	slices.Sort(shape.extensions)

	return shape
}

func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

type byteReader struct {
	t *testing.T
	b []byte
}

func (r *byteReader) take(n int) []byte {
	r.t.Helper()
	if n > len(r.b) {
		r.t.Fatalf("truncated ClientHello: need %d bytes, have %d", n, len(r.b))
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *byteReader) skip(n int)            { r.take(n) }
func (r *byteReader) uint8() uint8          { return r.take(1)[0] }
func (r *byteReader) uint16() uint16        { return binary.BigEndian.Uint16(r.take(2)) }
func (r *byteReader) sub(n int) *byteReader { return &byteReader{t: r.t, b: r.take(n)} }
