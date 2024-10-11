package probes

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// RdnsProbeData stores information about the reverse DNS lookup
type RdnsProbeData struct {
	ResolvedHosts []string
	TTL           time.Duration
}

// RdnsProbe performs a forward DNS lookup for the given hostname, then a reverse DNS lookup for the resolved IP address
func RdnsProbe(domain string, debug bool) (interface{}, error) {
	start := time.Now()

	// Perform a forward DNS lookup to get the IP address
	ips, err := net.LookupIP(domain)
	if err != nil {
		if debug {
			fmt.Printf("Forward lookup failed for domain '%s': %v\n", domain, err)
		}
		return &RdnsProbeData{
			ResolvedHosts: []string{},
			TTL:           0,
		}, err
	}

	// If debug is true, print the resolved IP addresses
	if debug {
		fmt.Printf("Forward lookup results for '%s': %v\n", domain, ips)
	}

	// Reverse DNS lookup for the first resolved IP address
	// Grab the first IPv4 address
	var ipv4 net.IP
	for _, ip := range ips {
		if ip := ip.To4(); ip != nil {
			ipv4 = ip
			break // Use the first IPv4 found
		}
	}

	if ipv4 == nil {
		if debug {
			fmt.Printf("No IPv4 addresses found for domain '%s'.\n", domain)
		}
		return &RdnsProbeData{
			ResolvedHosts: []string{},
			TTL:           0,
		}, fmt.Errorf("no IPv4 addresses found for domain '%s'", domain)
	}

	hosts, err := net.LookupAddr(ipv4.String())
	if err != nil {
		if debug {
			fmt.Printf("Reverse lookup failed for IP '%s': %v\n", ipv4, err)
		}
		return &RdnsProbeData{
			ResolvedHosts: []string{},
			TTL:           0,
		}, err
	}

	// Calculate the TTL as the time taken for the DNS lookup
	ttl := time.Since(start)

	// If debug is true, print the reverse lookup results
	if debug {
		fmt.Printf("Reverse lookup results for IP '%s': %v\n", ipv4, hosts)
		fmt.Printf("Lookup duration (TTL): %v\n", ttl)
	}

	// Trim trailing dots in resolved hostnames
	for i, host := range hosts {
		hosts[i] = strings.TrimSuffix(host, ".")
	}

	return &RdnsProbeData{
		ResolvedHosts: hosts,
		TTL:           ttl,
	}, nil
}
