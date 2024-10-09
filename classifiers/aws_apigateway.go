package classifiers

import (
	"magic-lb-classifier/probes"
	"regexp"
)

var apiGatewayRegex = regexp.MustCompile(`^[^.]+\.execute-api\.[^.]+\.amazonaws.com$`)

// Classifier for Regional API
func ClassifyRegionalAPI(probeResults map[string]interface{}) string {
	// Retrieve the probe data that we need
	httpData, ok := probeResults["HTTP"].(*probes.HttpProbeData)
	if !ok {
		// If the HTTP probe data is not available, return an empty string
		return ""
	}
	http10Data, ok := probeResults["HTTP_1.0"].(*probes.Http10ProbeData)
	if !ok {
		return ""
	}

	// 1. Should have an apigw-requestid on HTTP/1.1
	if httpData.HttpResponseHeaders["Apigw-Requestid"] == "" {
		return ""
	}

	// 2. Should not have a Cloudfront header on HTTP/1.0
	if http10Data.Http10ResponseHeaders["Server"] == "CloudFront" {
		return ""
	}

	// Check if there are at most 2 IPs and specific CloudFront headers are NOT present
	if len(httpData.IPv4) <= 2 && (httpData.HttpResponseHeaders["X-Amz-Cf-Pop"] == "" && httpData.HttpResponseHeaders["Via"] == "") {
		return "API Gateway: Regional API"
	}

	return ""
}

// ClassifyEdgeAPI implements a classifier for an API Gateway - edge API
func ClassifyEdgeAPI(probeResults map[string]interface{}) string {
	// Retrieve the probe data that we need
	httpData, ok := probeResults["HTTP"].(*probes.HttpProbeData)
	if !ok {
		return ""
	}
	http10Data, ok := probeResults["HTTP_1.0"].(*probes.Http10ProbeData)
	if !ok {
		return ""
	}

	// 1. Needs a request ID on HTTP1.1
	if httpData.HttpResponseHeaders["X-Amz-Apigw-Id"] == "" {
		return ""
	}

	// 2. Should have a Cloudfront header on HTTP1.0
	if http10Data.Http10ResponseHeaders["Server"] != "CloudFront" {
		return ""
	}

	// 3. Check if there are at least 4 IPs and the required CloudFront headers are present
	if len(httpData.IPv4) >= 4 && httpData.HttpResponseHeaders["X-Amz-Cf-Pop"] != "" && httpData.HttpResponseHeaders["Via"] != "" {
		return "API Gateway: Edge API"
	}

	return ""
}
