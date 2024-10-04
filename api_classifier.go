package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
)

// Info we need for classification. Will extend as we add more classifiers!
type DomainInfo struct {
	Domain              string            // Domain name
	IPv4                []string          // List of IPv4 addresses
	IPv6                []string          // List of IPv6 addresses
	CertIssuer          string            // Certificate Issuer (Amazon vs. non-Amazon)
	HttpResponseHeaders map[string]string // Map of HTTP response headers
}

// Extract relevant information from the HTTP response for classification
func extractDomainInfo(domain string) (*DomainInfo, error) {
	// Make a request to get the headers and TLS information
	req, err := http.NewRequest("GET", "https://"+domain, nil)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Ignore invalid certs for this example
		},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

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
	conn, err := tls.Dial("tcp", domain+":443", &tls.Config{InsecureSkipVerify: true})
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
		Domain:              domain,
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
}

// Regular expression for matching API Gateway hostnames
var apiGatewayRegex = regexp.MustCompile(`^[^.]+\.execute-api\.[^.]+\.amazonaws.com$`)
var albRegex = regexp.MustCompile(`^[^.]+\.[^.]+\.elb\.amazonaws.com$`)

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

// Main function
func main() {
	// Get the domain name from the CLI
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run api_classifier.go <domain-name>")
		return
	}
	domain := os.Args[1]

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

	fmt.Printf("Domain: %s\nClassification: %s\n", domainInfo.Domain, classification)
	fmt.Printf("IPv4: %v\nIPv6: %v\nCertIssuer: %s\n", domainInfo.IPv4, domainInfo.IPv6, domainInfo.CertIssuer)
}
