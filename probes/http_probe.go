package probes

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
)

type HttpProbeData struct {
	IPv4                []string
	IPv6                []string
	CertIssuer          string
	HttpResponseHeaders map[string]string
}

// HttpProbe probe function
func HttpProbe(domain string, debug bool) (interface{}, error) {
	// Create a custom transport with a TLS configuration so we can
	// turn off cert verification
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Disable TLS verification for testing
		},
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("GET", "https://"+domain, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	ipAddresses, err := net.LookupIP(resp.Request.URL.Hostname())
	if err != nil {
		return nil, err
	}

	var ipv4 []string
	var ipv6 []string
	for _, ip := range ipAddresses {
		if ip.To4() != nil {
			ipv4 = append(ipv4, ip.String())
		} else {
			ipv6 = append(ipv6, ip.String())
		}
	}

	conn, err := tls.Dial("tcp", domain+":443", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	cert := conn.ConnectionState().PeerCertificates[0]
	certIssuer := "Non-Amazon"
	if strings.Contains(cert.Subject.CommonName, ".amazonaws.com") {
		certIssuer = "Amazon"
	}

	headers := make(map[string]string)
	for key, values := range resp.Header {
		headers[key] = values[0]
	}

	if debug {
		printHeaders("HTTP Probe", headers)
		printTLSInfo(resp.TLS)
	}

	return &HttpProbeData{
		IPv4:                ipv4,
		IPv6:                ipv6,
		CertIssuer:          certIssuer,
		HttpResponseHeaders: headers,
	}, nil
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
