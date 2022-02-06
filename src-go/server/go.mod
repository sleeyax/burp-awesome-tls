module server

go 1.17

require (
	github.com/refraction-networking/utls v1.0.0
	golang.org/x/net v0.0.0-20220127200216-cd36cc0744dd
	golang.org/x/term v0.0.0-20210927222741-03fcf44c2211
)

require (
	github.com/andybalholm/brotli v1.0.4 // indirect
	github.com/klauspost/compress v1.13.6 // indirect
	golang.org/x/crypto v0.0.0-20220131195533-30dcbda58838 // indirect
	golang.org/x/sys v0.0.0-20211216021012-1d35b9e2eb4e // indirect
	golang.org/x/text v0.3.7 // indirect
)

replace golang.org/x/net/http => ./server/internal/net/http

replace golang.org/x/net/http2 => ./server/internal/net/http2

replace github.com/refraction-networking/utls => github.com/sleeyax/utls v1.1.1
