package main

import "C"

import (
	"flag"
	"fmt"
	"log"

	"server"
)

func main() {
	interceptAddr := flag.String("intercept", server.DefaultInterceptProxyAddress, "Intercept proxy address to listen on ([ip:]port)")
	burpAddr := flag.String("burp", server.DefaultBurpProxyAddress, "Burp proxy address to listen on ([ip:]port)")
	spoofAddr := flag.String("spoof", server.DefaultSpoofProxyAddress, "Spoof proxy address to listen on ([ip:]port)")
	flag.Parse()

	addresses := server.ListenAddresses{}
	if interceptAddr != nil {
		addresses.InterceptAddr = *interceptAddr
	}
	if burpAddr != nil {
		addresses.BurpAddr = *burpAddr
	}
	if spoofAddr != nil {
		addresses.SpoofAddr = *spoofAddr
	}

	log.Fatalln(server.StartServer(addresses))
}

//export StartServer
func StartServer(interceptAddr, burpAddr, spoofAddr *C.char) *C.char {
	if err := server.StartServer(server.ListenAddresses{
		InterceptAddr: C.GoString(interceptAddr),
		BurpAddr:      C.GoString(burpAddr),
		SpoofAddr:     C.GoString(spoofAddr),
	}); err != nil {
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

//export SmokeTest
func SmokeTest() {
	fmt.Println("smoke test success")
}
