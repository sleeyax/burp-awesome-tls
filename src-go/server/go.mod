module server

go 1.17

require golang.org/x/net v0.0.0-20220127200216-cd36cc0744dd

require golang.org/x/text v0.3.7 // indirect

replace golang.org/x/net/http => ./server/internal/net/http
