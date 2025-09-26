module server

go 1.24.1

toolchain go1.25.1

require (
	github.com/bogdanfinn/fhttp v0.6.2
	github.com/bogdanfinn/tls-client v1.8.0
	github.com/bogdanfinn/utls v1.7.4-barnius
)

require (
	github.com/andybalholm/brotli v1.1.1 // indirect
	github.com/cloudflare/circl v1.5.0 // indirect
	github.com/klauspost/compress v1.17.11 // indirect
	github.com/quic-go/quic-go v0.48.1 // indirect
	github.com/tam7t/hpkp v0.0.0-20160821193359-2b70b4024ed5 // indirect
	golang.org/x/crypto v0.36.0 // indirect
	golang.org/x/net v0.38.0 // indirect
	golang.org/x/sys v0.31.0 // indirect
	golang.org/x/text v0.23.0 // indirect
)

replace github.com/ooni/oohttp => github.com/sleeyax/oohttp v0.0.0-20230603105812-6ac0447b1a8e
