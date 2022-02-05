package server

import (
	"fmt"
	"net/url"
)

// toTCPAddress converts a URL to a TCP address string.
func toTCPAddress(u *url.URL) string {
	host := u.Hostname()

	var port string
	if p := u.Port(); p != "" {
		port = p
	} else if u.Scheme == "http" {
		port = "80"
	} else {
		port = "443"
	}

	return fmt.Sprintf("%s:%s", host, port)
}
