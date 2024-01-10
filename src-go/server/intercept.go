package server

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strings"
	"sync"
	"syscall"

	http "github.com/ooni/oohttp"
	"github.com/open-ch/ja3"
)

const tlsClientHelloMsgType = "16"

type interceptProxy struct {
	burpClient      *http.Client
	burpAddr        string
	mutex           sync.RWMutex
	clientHelloData map[string]string
	listener        net.Listener
	ctx             context.Context
	cancel          context.CancelFunc
}

func newInterceptProxy(interceptAddr, burpAddr string) (*interceptProxy, error) {
	proxyURL, err := url.Parse(fmt.Sprintf("http://%s", burpAddr))
	if err != nil {
		return nil, err
	}

	tr := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}

	l, err := net.Listen("tcp", interceptAddr)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &interceptProxy{
		burpClient: &http.Client{
			Transport: tr,
		},
		burpAddr:        burpAddr,
		mutex:           sync.RWMutex{},
		clientHelloData: map[string]string{},
		listener:        l,
		ctx:             ctx,
		cancel:          cancel,
	}, nil
}

func (s *interceptProxy) getTLSFingerprint(sni string) string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return s.clientHelloData[sni]
}

func (s *interceptProxy) Start() {
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			conn, err := s.listener.Accept()
			if err != nil {
				log.Println(err)
				continue
			}

			go s.handleConn(conn)
		}
	}
}

func (s *interceptProxy) Stop() error {
	s.cancel()
	return s.listener.Close()
}

func (s *interceptProxy) handleConn(in net.Conn) {
	defer in.Close()

	out, err := net.Dial("tcp", s.burpAddr)
	if err != nil {
		s.writeError(err)
		return
	}

	defer out.Close()

	var readClientHello bool
	var length uint16
	var clientHello []byte

	inReader := io.TeeReader(in, out)
	outReader := io.TeeReader(out, in)

	var wg sync.WaitGroup

	wg.Add(2)

	go func() {
		defer wg.Done()

		for {
			if readClientHello {
				_, err = io.ReadAll(inReader)
				if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET) && !errors.Is(err, syscall.EPIPE) {
					s.writeError(err)
				}

				return
			}

			buf := make([]byte, 1)
			if _, err = inReader.Read(buf); err != nil {
				s.writeError(err)
				return
			}

			// catch ClientHello message type
			if hex.EncodeToString(buf) != tlsClientHelloMsgType {
				continue
			}

			clientHello = append(clientHello, buf...)

			// read tls version
			buf = make([]byte, 2)
			if _, err = inReader.Read(buf); err != nil {
				s.writeError(err)
				return
			}

			clientHello = append(clientHello, buf...)

			// read client hello length
			buf = make([]byte, 2)
			if _, err = inReader.Read(buf); err != nil {
				s.writeError(err)
				return
			}

			length = binary.BigEndian.Uint16(buf)
			clientHello = append(clientHello, buf...)

			// read remaining client hello by length
			buf = make([]byte, length)
			if _, err = inReader.Read(buf); err != nil {
				s.writeError(err)
				return
			}

			clientHello = append(clientHello, buf...)

			readClientHello = true

			j, err := ja3.ComputeJA3FromSegment(clientHello)
			if err != nil {
				s.writeError(err)
				return
			}
<<<<<<< Updated upstream
			
			s.mutex.Lock()
			s.clientHelloData[j.GetSNI()] = hex.EncodeToString(clientHello)
			s.mutex.Unlock()
			
=======

			s.mutex.Lock()
			s.clientHelloData[j.GetSNI()] = hex.EncodeToString(clientHello)
			s.mutex.Unlock()
>>>>>>> Stashed changes
		}
	}()

	go func() {
		defer wg.Done()

		_, err = io.ReadAll(outReader)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET) && !errors.Is(err, syscall.EPIPE) {
			s.writeError(err)
		}
	}()

	wg.Wait()
}

func (s *interceptProxy) writeError(err error) {
	if errors.Is(err, io.EOF) {
		return
	}

	log.Println(err)

	reqErr := strings.NewReader(fmt.Sprintf("Awesome TLS intercept proxy error: %s", err.Error()))
	req, err := http.NewRequest("POST", "http://awesome-tls-error", reqErr)
	if err != nil {
		log.Println(err)
	}

	_, err = s.burpClient.Do(req)
	if err != nil {
		log.Println(err)
	}
}
