package server

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	"github.com/open-ch/ja3"
)

const tlsClientHelloMsgType = "16"

type interceptProxy struct {
	burpAddr        string
	mutex           sync.RWMutex
	clientHelloData map[string]string
	listener        net.Listener
}

func newInterceptProxy(interceptAddr, burpAddr string) (*interceptProxy, error) {
	l, err := net.Listen("tcp", interceptAddr)
	if err != nil {
		return nil, err
	}

	s := interceptProxy{
		burpAddr:        burpAddr,
		mutex:           sync.RWMutex{},
		clientHelloData: map[string]string{},
		listener:        l,
	}

	go s.start()

	return &s, nil
}

func (s *interceptProxy) getTLSFingerprint(sni string) string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return s.clientHelloData[sni]
}

func (s *interceptProxy) start() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			log.Println(err)
		}

		go s.handleConn(conn)
	}
}

func (s *interceptProxy) handleConn(in net.Conn) {
	defer in.Close()

	out, err := net.Dial("tcp", s.burpAddr)
	if err != nil {
		return
	}

	defer out.Close()

	var readClientHello bool
	var length uint16
	var clientHello []byte

	r := io.TeeReader(in, out)

	var wg sync.WaitGroup

	wg.Add(2)

	go func() {
		for {
			var buf []byte

			buf = make([]byte, 1)
			if _, err := r.Read(buf); err != nil {
				return
			}

			if readClientHello {
				buf = make([]byte, 1)
				if _, err := r.Read(buf); err != nil {
					return
				}

				continue
			}

			// catch ClientHello message type
			if hex.EncodeToString(buf) != tlsClientHelloMsgType {
				continue
			}

			clientHello = append(clientHello, buf...)

			// read tls version
			buf = make([]byte, 2)
			if _, err := r.Read(buf); err != nil {
				return
			}

			clientHello = append(clientHello, buf...)

			// read client hello length
			buf = make([]byte, 2)
			if _, err := r.Read(buf); err != nil {
				return
			}

			length = binary.BigEndian.Uint16(buf)
			clientHello = append(clientHello, buf...)

			// read remaining client hello by length
			buf = make([]byte, length)
			if _, err := r.Read(buf); err != nil {
				return
			}

			clientHello = append(clientHello, buf...)

			readClientHello = true

			j, err := ja3.ComputeJA3FromSegment(clientHello)
			if err != nil {
				fmt.Println(err)
			} else {
				s.mutex.Lock()
				s.clientHelloData[j.GetSNI()] = hex.EncodeToString(clientHello)
				s.mutex.Unlock()
			}
		}
	}()

	go func() {
		for {
			buf := make([]byte, 1)
			if _, err := out.Read(buf); err != nil {
				return
			}

			if _, err := in.Write(buf); err != nil {
				return
			}
		}
	}()

	wg.Wait()
}
