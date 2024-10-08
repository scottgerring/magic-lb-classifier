package classifiers

import (
	"magic-lb-classifier/domain_info"
	"regexp"
)

var apiGatewayRegex = regexp.MustCompile(`^[^.]+\.execute-api\.[^.]+\.amazonaws.com$`)

// Classifier for Regional API
func ClassifyRegionalAPI(info *domain_info.DomainInfo) string {
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
func ClassifyEdgeAPI(info *domain_info.DomainInfo) string {
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
