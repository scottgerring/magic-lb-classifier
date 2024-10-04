package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
)

// Info we need for classification. Will extend as we add more classifiers!
type DomainInfo struct {
	Domain              string            // Domain name
	IPs                 []string          // List of IPs
	HttpResponseHeaders map[string]string // Map of HTTP response headers
}

// Extract relevant information from the HTTP response for classification
func extractDomainInfo(domain string) (*DomainInfo, error) {
	// Make a request to get the headers
	resp, err := http.Get("https://" + domain)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Extract IP addresses
	ipAddresses, err := net.LookupIP(resp.Request.URL.Hostname())
	if err != nil {
		return nil, err
	}

	// Copy headers across
	headers := make(map[string]string)
	for key, values := range resp.Header {
		headers[key] = values[0] // Only take the first value for simplicity
	}

	// Return the extracted information
	domainInfo := &DomainInfo{
		Domain:              domain,
		IPs:                 make([]string, len(ipAddresses)),
		HttpResponseHeaders: headers,
	}

	// Append IP addresses to DomainInfo
	for i, ip := range ipAddresses {
		domainInfo.IPs[i] = ip.String() // Store actual IPs
	}

	return domainInfo, nil
}

// Classifier function types
type ClassifierFunc func(*DomainInfo) string

// List of classifiers
var classifiers = []ClassifierFunc{
	classifyRegionalAPI,
	classifyEdgeAPI,
}

// Regular expression for matching API Gateway hostnames
var apiGatewayRegex = regexp.MustCompile(`^[^.]+\.execute-api\.[^.]+\.amazonaws.com$`)

// Classifier for Regional API
func classifyRegionalAPI(info *DomainInfo) string {
	// Check if the domain matches the API Gateway pattern
	if !apiGatewayRegex.MatchString(info.Domain) {
		return ""
	}

	// Check if there are at most 2 IPs and specific CloudFront headers are NOT present
	if len(info.IPs) <= 2 && (info.HttpResponseHeaders["X-Amz-Cf-Pop"] == "" && info.HttpResponseHeaders["Via"] == "") {
		return "Regional API"
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
	if len(info.IPs) >= 4 && info.HttpResponseHeaders["X-Amz-Cf-Pop"] != "" && info.HttpResponseHeaders["Via"] != "" {
		return "Edge API"
	}
	return ""
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
	classification := "Something else"
	for _, classifier := range classifiers {
		result := classifier(domainInfo)
		if result != "" {
			classification = result
			break
		}
	}

	fmt.Println(classification)
}
