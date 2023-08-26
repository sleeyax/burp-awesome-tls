package server

import "testing"

func TestStartServer(t *testing.T) {
	if err := StartServer(ListenAddresses{
		BurpAddr:      DefaultBurpProxyAddress,
		SpoofAddr:     DefaultSpoofProxyAddress,
		InterceptAddr: DefaultInterceptProxyAddress,
	}); err != nil {
		t.Fatal(err)
	}

	if err := StopServer(); err != nil {
		t.Fatal(err)
	}
}
