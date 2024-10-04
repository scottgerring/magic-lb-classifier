package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
)

// Global debug flag
var debug = false

// Info we need for classification. Will extend as we add more classifiers!
type DomainInfo struct {
	Domain              string            // Resolved domain name
	OriginalDomain      string            // Original input domain name
	IPv4                []string          // List of IPv4 addresses
	IPv6                []string          // List of IPv6 addresses
	CertIssuer          string            // Certificate Issuer (Amazon vs. non-Amazon)
	HttpResponseHeaders map[string]string // Map of HTTP response headers
}

// ResolveCNAME checks if the given domain is a CNAME and resolves it
func resolveCNAME(domain string) (string, error) {
	// Perform a CNAME lookup
	cname, err := net.LookupCNAME(domain)
	if err != nil {
		return domain, nil // If no CNAME is found, return the original domain
	}
	return strings.TrimSuffix(cname, "."), nil // Remove trailing dot from CNAME
}

// Debug function to print detailed TLS information
func printTLSInfo(connState *tls.ConnectionState) {
	if debug {
		fmt.Println("=== TLS Connection Details ===")
		fmt.Printf("TLS Version: %v\n", tlsVersionToString(connState.Version))
		fmt.Printf("Cipher Suite: %v\n", tlsCipherSuiteToString(connState.CipherSuite))

		for _, cert := range connState.PeerCertificates {
			fmt.Printf("Certificate Subject: %s\n", cert.Subject)
			fmt.Printf("Certificate Issuer: %s\n", cert.Issuer)
		}
		fmt.Println("==============================")
	}
}

// Debug function to print detailed HTTP headers
func printHeaders(headers http.Header) {
	if debug {
		fmt.Println("=== HTTP Response Headers ===")
		for key, values := range headers {
			for _, value := range values {
				fmt.Printf("%s: %s\n", key, value)
			}
		}
		fmt.Println("==============================")
	}
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

// Extract relevant information from the HTTP response for classification
func extractDomainInfo(domain string) (*DomainInfo, error) {
	// Resolve CNAME if present
	resolvedDomain, err := resolveCNAME(domain)
	if err != nil {
		return nil, err
	}

	// Create a custom transport with a TLS configuration
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Disable TLS verification for testing
			GetClientCertificate: func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
				if debug {
					log.Printf("Client Certificate Requested: %+v\n", info)
				}
				return nil, nil
			},
		},
	}

	client := &http.Client{Transport: tr}

	// Make a request to get the headers and TLS information
	req, err := http.NewRequest("GET", "https://"+resolvedDomain, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Print some debugging bits if debugging is on
	printTLSInfo(resp.TLS)
	printHeaders(resp.Header)

	// Extract IP addresses
	ipAddresses, err := net.LookupIP(resp.Request.URL.Hostname())
	if err != nil {
		return nil, err
	}

	// Separate IPv4 and IPv6 addresses
	var ipv4 []string
	var ipv6 []string
	for _, ip := range ipAddresses {
		if ip.To4() != nil {
			ipv4 = append(ipv4, ip.String())
		} else {
			ipv6 = append(ipv6, ip.String())
		}
	}

	// Extract certificate information
	conn, err := tls.Dial("tcp", resolvedDomain+":443", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	cert := conn.ConnectionState().PeerCertificates[0]

	// Determine if it's an Amazon-issued cert
	certIssuer := "Non-Amazon"
	if strings.Contains(cert.Subject.CommonName, ".amazonaws.com") {
		certIssuer = "Amazon"
	}

	// Copy headers across
	headers := make(map[string]string)
	for key, values := range resp.Header {
		headers[key] = values[0] // Only take the first value for simplicity
	}

	// Return the extracted information
	domainInfo := &DomainInfo{
		Domain:              resolvedDomain,
		OriginalDomain:      domain,
		IPv4:                ipv4,
		IPv6:                ipv6,
		CertIssuer:          certIssuer,
		HttpResponseHeaders: headers,
	}

	return domainInfo, nil
}

// Classifier function types
type ClassifierFunc func(*DomainInfo) string

// List of classifiers
var classifiers = []ClassifierFunc{
	classifyRegionalAPI,
	classifyEdgeAPI,
	classifyALB,
	classifyNLB,
}

// Regular expression for matching API Gateway hostnames
var apiGatewayRegex = regexp.MustCompile(`^[^.]+\.execute-api\.[^.]+\.amazonaws.com$`)
var albRegex = regexp.MustCompile(`^[^.]+\.[^.]+\.elb\.amazonaws.com$`) // blob.us-east-1.amazonaws.com
var nlbRegex = regexp.MustCompile(`^[^.]+\.elb\.[^.]+\.amazonaws.com$`) // blob.elb.us-east-1.amazonaws.com

// Classifier for Regional API
func classifyRegionalAPI(info *DomainInfo) string {
	// Check if the domain matches the API Gateway pattern
	if !apiGatewayRegex.MatchString(info.Domain) {
		return ""
	}

	// Check if there are at most 2 IPs and specific CloudFront headers are NOT present
	if len(info.IPv4) <= 2 && (info.HttpResponseHeaders["X-Amz-Cf-Pop"] == "" && info.HttpResponseHeaders["Via"] == "") {
		return "API Gateway: Regional API"
	}
	return ""
}

// Classifier for API Gateway Edge API
func classifyEdgeAPI(info *DomainInfo) string {
	// Check if the domain matches the API Gateway pattern
	if !apiGatewayRegex.MatchString(info.Domain) {
		return ""
	}

	// Check if there are at least 4 IPs and the required CloudFront headers are present
	if len(info.IPv4) >= 4 && info.HttpResponseHeaders["X-Amz-Cf-Pop"] != "" && info.HttpResponseHeaders["Via"] != "" {
		return "API Gateway: Edge API"
	}
	return ""
}

// Classifier for ALB
func classifyALB(info *DomainInfo) string {
	// Check if the domain matches the ALB pattern
	if !albRegex.MatchString(info.Domain) {
		return ""
	}

	// ALBs often resolve IPv6 addresses, so check for that
	if len(info.IPv6) > 0 {
		return "ALB (IPv6-enabled)"
	}
	return "ALB"
}

// Classifier for NLB
func classifyNLB(info *DomainInfo) string {
	if !nlbRegex.MatchString(info.Domain) {
		return ""
	}

	// ALBs often resolve IPv6 addresses, so check for that
	if len(info.IPv6) > 0 {
		return "NLB (IPv6-enabled)"
	}

	return "NLB"
}

// Main function
func main() {
	// Get the domain name and optional debug flag from the CLI
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run api_classifier.go <domain-name> [--debug]")
		return
	}
	domain := os.Args[1]

	// Check for --debug flag
	if len(os.Args) > 2 && os.Args[2] == "--debug" {
		debug = true
	}

	// Extract domain information
	domainInfo, err := extractDomainInfo(domain)
	if err != nil {
		fmt.Printf("Error fetching domain information: %v\n", err)
		return
	}

	// Classify the domain using the classifiers
	classification := "Unknown"
	for _, classifier := range classifiers {
		result := classifier(domainInfo)
		if result != "" {
			classification = result
			break
		}
	}

	fmt.Printf("IPv4: %v\nIPv6: %v\nCertIssuer: %s\n", domainInfo.IPv4, domainInfo.IPv6, domainInfo.CertIssuer)
	fmt.Printf("Original Domain: %s\nResolved Domain: %s\nClassification: %s\n", domainInfo.OriginalDomain, domainInfo.Domain, classification)

}
