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
	emulateAddr := flag.String("emulate", server.DefaultEmulateProxyAddress, "Emulate proxy address to listen on ([ip:]port)")
	flag.Parse()

	addresses := server.ListenAddresses{}
	if interceptAddr != nil {
		addresses.InterceptAddr = *interceptAddr
	}
	if burpAddr != nil {
		addresses.BurpAddr = *burpAddr
	}
	if emulateAddr != nil {
		addresses.EmulateAddr = *emulateAddr
	}

	log.Fatalln(server.StartServer(addresses))
}

//export StartServer
func StartServer(interceptProxy, burpProxy, emulateProxy string) *C.char {
	if err := server.StartServer(server.ListenAddresses{
		InterceptAddr: interceptProxy,
		BurpAddr:      burpProxy,
		EmulateAddr:   emulateProxy,
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
