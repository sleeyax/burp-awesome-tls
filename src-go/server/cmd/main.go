package main

import "C"

import (
	"flag"
	"fmt"
	"log"
	"server"
	"strings"
)

func main() {
	spoofAddr := flag.String("spoof", "", "Spoof proxy address to listen on ([ip:]port)")
	flag.Parse()

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

//export SmokeTest
func SmokeTest() {
	fmt.Println("smoke test success")
}

//export GetFingerprints
func GetFingerprints() *C.char {
	return C.CString(strings.Join(server.GetFingerprints(), "\n"))
}
