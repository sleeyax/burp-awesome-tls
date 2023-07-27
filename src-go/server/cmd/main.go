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
	log.Fatalln(server.StartServer(*interceptAddr, *burpAddr, *emulateAddr))
}

//export StartServer
func StartServer(interceptAddr, burpAddr, emulateAddr *C.char) *C.char {
	if err := server.StartServer(C.GoString(interceptAddr), C.GoString(burpAddr), C.GoString(emulateAddr)); err != nil {
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
