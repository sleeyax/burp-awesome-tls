package main

import "C"

import (
	"flag"
	"fmt"
	"log"

	"server"
)

func main() {
	spoofAddr := flag.String("spoof", server.DefaultSpoofProxyAddress, "Spoof proxy address to listen on ([ip:]port)")
	flag.Parse()

	settings := `{"InterceptProxyAddr":":8886","BurpAddr":"127.0.0.1:8080","Fingerprint":"Firefox 105","UseInterceptedFingerprint":true,"HttpTimeout":30,"HttpKeepAliveInterval":30,"IdleConnTimeout":90,"TlsHandshakeTimeout":10}`
	if err := server.SaveSettings(settings); err != nil {
		log.Fatalln(err)
	}

	log.Fatalln(server.StartServer(*spoofAddr))
}

//export StartServer
func StartServer(spoofAddr *C.char) *C.char {
	if err := server.StartServer(C.GoString(spoofAddr)); err != nil {
		return C.CString(err.Error())
	}
	return C.CString("")
}

//export StopServer
func StopServer() *C.char {
	if err := server.StopServer(); err != nil {
		return C.CString(err.Error())
	}
	return C.CString("")
}

//export SaveSettings
func SaveSettings(configJson *C.char) *C.char {
	if err := server.SaveSettings(C.GoString(configJson)); err != nil {
		return C.CString(err.Error())
	}

	return C.CString("")
}

//export SmokeTest
func SmokeTest() {
	fmt.Println("smoke test success")
}
