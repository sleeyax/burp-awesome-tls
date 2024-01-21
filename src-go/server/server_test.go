package server

import "testing"

func TestStartServer(t *testing.T) {
	if err := StartServer(DefaultSpoofProxyAddress); err != nil {
		t.Fatal(err)
	}

	if err := StopServer(); err != nil {
		t.Fatal(err)
	}
}
