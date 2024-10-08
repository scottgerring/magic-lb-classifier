package classifiers

import (
	"magic-lb-classifier/probes"
	"regexp"
)

var apiGatewayRegex = regexp.MustCompile(`^[^.]+\.execute-api\.[^.]+\.amazonaws.com$`)

// Classifier for Regional API
func ClassifyRegionalAPI(probeResults map[string]interface{}) string {
	// Retrieve the HTTP probe data from the map
	httpData, ok := probeResults["HTTP"].(*probes.HttpProbeData)
	if !ok {
		// If the HTTP probe data is not available, return an empty string
		return ""
	}

	// Check if the domain matches the API Gateway pattern
	cnameData, ok := probeResults["CNAME"].(*probes.CnameProbeData)
	if !ok {
		return ""
	}
	if !apiGatewayRegex.MatchString(cnameData.ResolvedDomain) {
		return ""
	}

	// Check if there are at most 2 IPs and specific CloudFront headers are NOT present
	if len(httpData.IPv4) <= 2 && (httpData.HttpResponseHeaders["X-Amz-Cf-Pop"] == "" && httpData.HttpResponseHeaders["Via"] == "") {
		return "API Gateway: Regional API"
	}

	return ""
}

// Classifier for API Gateway Edge API
func ClassifyEdgeAPI(probeResults map[string]interface{}) string {
	// Retrieve the HTTP probe data from the map
	httpData, ok := probeResults["HTTP"].(*probes.HttpProbeData)
	if !ok {
		// If the HTTP probe data is not available, return an empty string
		return ""
	}

	// Check if the domain matches the API Gateway pattern
	cnameData, ok := probeResults["CNAME"].(*probes.CnameProbeData)
	if !ok {
		return ""
	}
	if !apiGatewayRegex.MatchString(cnameData.ResolvedDomain) {
		return ""
	}

	// Check if there are at least 4 IPs and the required CloudFront headers are present
	if len(httpData.IPv4) >= 4 && httpData.HttpResponseHeaders["X-Amz-Cf-Pop"] != "" && httpData.HttpResponseHeaders["Via"] != "" {
		return "API Gateway: Edge API"
	}

	return ""
}
