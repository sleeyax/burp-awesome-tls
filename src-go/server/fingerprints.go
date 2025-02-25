package server

import (
	"github.com/bogdanfinn/tls-client/profiles"
	"maps"
	"slices"
)

func GetFingerprints() []string {
	fingerprints := slices.Sorted(maps.Keys(profiles.MappedTLSClients))
	return append([]string{"default"}, fingerprints...)
}
