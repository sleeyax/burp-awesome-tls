package main

import "C"

import (
	"flag"
	"fmt"
	"log"

	"server"
)

func main() {
	addr := flag.String("a", server.DefaultAddress, "Address to listen on ([ip:]port)")
	flag.Parse()
	log.Fatalln(server.StartServer(*addr))
}

//export StartServer
func StartServer(address *C.char) *C.char {
	if err := server.StartServer(C.GoString(address)); err != nil {
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
