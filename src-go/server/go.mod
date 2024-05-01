module server

go 1.21

toolchain go1.22.2

require (
	github.com/ooni/oohttp v0.7.1
	github.com/open-ch/ja3 v1.0.1
	github.com/refraction-networking/utls v1.6.4
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/cloudflare/circl v1.3.7 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	golang.org/x/crypto v0.18.0 // indirect
	golang.org/x/net v0.20.0 // indirect
	golang.org/x/sys v0.16.0 // indirect
	golang.org/x/text v0.14.0 // indirect
)

replace github.com/ooni/oohttp => github.com/sleeyax/oohttp v0.0.0-20230603105812-6ac0447b1a8e
