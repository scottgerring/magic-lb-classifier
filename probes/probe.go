package probes

import (
	"crypto/tls"
	"fmt"
	"log"
)

type ProbeFunc func(domain string, debug bool) (interface{}, error)

// All our probes go here
var probeFuncMap map[string]ProbeFunc

func init() {
	probeFuncMap = map[string]ProbeFunc{
		"HTTP":     HttpProbe,
		"HTTP_1.0": Http10Probe,
		"CNAME":    CnameProbe,
		"RDNS":     RdnsProbe,
	}
}

// ProbeDomain function that uses the global map of probe functions
func ProbeDomain(domain string, debug bool) (map[string]interface{}, error) {
	// Initialize the map that will hold the probe results
	results := make(map[string]interface{})

	// Iterate over all registered probes and execute each one
	for probeName, probeFunc := range probeFuncMap {
		// Execute the probe function, passing the domain
		data, err := probeFunc(domain, debug)
		if err != nil {
			// Handle the error appropriately, e.g., log it and continue with other probes
			log.Printf("Error running probe %s: %v", probeName, err)
			continue
		}
		// Store the result using the probe name as the key
		results[probeName] = data
	}

	return results, nil
}

// Helper to convert cipher suite to string
func tlsCipherSuiteToString(cipherSuite uint16) string {
	switch cipherSuite {
	case tls.TLS_AES_128_GCM_SHA256:
		return "TLS_AES_128_GCM_SHA256"
	case tls.TLS_AES_256_GCM_SHA384:
		return "TLS_AES_256_GCM_SHA384"
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		return "TLS_CHACHA20_POLY1305_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	default:
		return "Unknown"
	}
}

// Debug function to print detailed TLS information
func printTLSInfo(connState *tls.ConnectionState) {
	fmt.Println("=== TLS Connection Details ===")
	fmt.Printf("TLS Version: %v\n", tlsVersionToString(connState.Version))
	fmt.Printf("Cipher Suite: %v\n", tlsCipherSuiteToString(connState.CipherSuite))

	for _, cert := range connState.PeerCertificates {
		fmt.Printf("Certificate Subject: %s\n", cert.Subject)
		fmt.Printf("Certificate Issuer: %s\n", cert.Issuer)
	}
	fmt.Println("==============================")

}

// Debug function to print detailed HTTP headers
func printHeaders(title string, headers map[string]string) {
	fmt.Printf("=== %s ===\n", title)
	for key, value := range headers {
		fmt.Printf("%s: %s\n", key, value)
	}
	fmt.Println("==============================")
}

// Helper to convert TLS version to string
func tlsVersionToString(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return "Unknown"
	}
}
