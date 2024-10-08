package probes

import (
	"net"
	"strings"
)

type CnameProbeData struct {
	WasCname       bool
	ResolvedDomain string
}

// CnameProbe checks if the given domain is a CNAME and resolves it
func CnameProbe(domain string, debug bool) (interface{}, error) {
	// Perform a CNAME lookup
	cname, err := net.LookupCNAME(domain)
	if err != nil {
		return &CnameProbeData{
			WasCname:       false,
			ResolvedDomain: domain,
		}, nil // If no CNAME is found, return the original domain
	}
	return &CnameProbeData{
		WasCname:       true,
		ResolvedDomain: strings.TrimSuffix(cname, "."),
	}, nil
}
