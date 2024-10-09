package main

import (
	"magic-lb-classifier/classifiers"
	"magic-lb-classifier/probes"
	"testing"
)

func TestClassifyRegionalAPI(t *testing.T) {
	tests := []struct {
		name         string
		probeResults map[string]interface{}
		expected     string
	}{
		{
			name: "Match Regional API",
			probeResults: map[string]interface{}{
				"HTTP": &probes.HttpProbeData{
					IPv4: []string{"1.2.3.4", "5.6.7.8"},
					HttpResponseHeaders: map[string]string{
						"Apigw-Requestid": "12345",
					},
				},
				"CNAME": &probes.CnameProbeData{
					WasCname:       true,
					ResolvedDomain: "myhost.execute-api.us-east-2.amazonaws.com",
				},
				"HTTP_1.0": &probes.Http10ProbeData{
					Http10ResponseHeaders: map[string]string{},
				},
			},
			expected: "API Gateway: Regional API",
		},
		{
			name: "Not Match Regional API - More than 2 IPs",
			probeResults: map[string]interface{}{
				"HTTP": &probes.HttpProbeData{
					IPv4: []string{"1.2.3.4", "5.6.7.8", "9.10.11.12"},
					HttpResponseHeaders: map[string]string{
						"Apigw-Requestid": "12345",
					},
				},
				"CNAME": &probes.CnameProbeData{
					WasCname:       true,
					ResolvedDomain: "myhost.execute-api.us-east-2.amazonaws.com",
				},
				"HTTP_1.0": &probes.Http10ProbeData{
					Http10ResponseHeaders: map[string]string{},
				},
			},
			expected: "",
		},
		{
			name: "Not Match Regional API - CloudFront headers present on HTTP/1.1",
			probeResults: map[string]interface{}{
				"HTTP": &probes.HttpProbeData{
					IPv4:                []string{"1.2.3.4", "5.6.7.8"},
					HttpResponseHeaders: map[string]string{"X-Amz-Cf-Pop": "some-value", "Via": "1.1", "Apigw-Requestid": "12345"},
				},
				"CNAME": &probes.CnameProbeData{
					WasCname:       true,
					ResolvedDomain: "myhost.execute-api.us-east-2.amazonaws.com",
				},
				"HTTP_1.0": &probes.Http10ProbeData{
					Http10ResponseHeaders: map[string]string{},
				},
			},
			expected: "",
		},
		{
			name: "Not Match Regional API - Cloudfront headers on HTTP/1.0",
			probeResults: map[string]interface{}{
				"HTTP": &probes.HttpProbeData{
					IPv4: []string{"1.2.3.4"},
					HttpResponseHeaders: map[string]string{
						"Apigw-Requestid": "12345",
					},
				},
				"CNAME": &probes.CnameProbeData{
					WasCname:       false,
					ResolvedDomain: "not-an-api.com",
				},
				"HTTP_1.0": &probes.Http10ProbeData{
					Http10ResponseHeaders: map[string]string{
						"Server": "CloudFront",
					},
				},
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifiers.ClassifyRegionalAPI(tt.probeResults)
			if got != tt.expected {
				t.Errorf("ClassifyRegionalAPI() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestClassifyEdgeAPI(t *testing.T) {
	tests := []struct {
		name         string
		probeResults map[string]interface{}
		expected     string
	}{
		{
			name: "Match Edge API",
			probeResults: map[string]interface{}{
				"HTTP": &probes.HttpProbeData{
					IPv4: []string{"1.2.3.4", "5.6.7.8", "9.10.11.12", "11.12.13.14"},
					HttpResponseHeaders: map[string]string{
						"X-Amz-Apigw-Id": "12345",
						"X-Amz-Cf-Pop":   "some-value",
						"Via":            "1.1"},
				},
				"HTTP_1.0": &probes.Http10ProbeData{
					Http10ResponseHeaders: map[string]string{"Server": "CloudFront"},
				},
				"CNAME": &probes.CnameProbeData{
					WasCname:       true,
					ResolvedDomain: "myhost.execute-api.us-east-2.amazonaws.com",
				},
			},
			expected: "API Gateway: Edge API",
		},
		{
			name: "Not Match Edge API - Less than 4 IPs",
			probeResults: map[string]interface{}{
				"HTTP": &probes.HttpProbeData{
					IPv4:                []string{"1.2.3.4", "5.6.7.8"},
					HttpResponseHeaders: map[string]string{"X-Amz-Cf-Pop": "some-value", "Via": "1.1"},
				},
				"CNAME": &probes.CnameProbeData{
					WasCname:       true,
					ResolvedDomain: "myhost.execute-api.us-east-2.amazonaws.com",
				},
			},
			expected: "",
		},
		{
			name: "Not Match Edge API - CloudFront headers not present",
			probeResults: map[string]interface{}{
				"HTTP": &probes.HttpProbeData{
					IPv4: []string{"1.2.3.4", "5.6.7.8", "9.10.11.12", "11.12.13.14"},
					HttpResponseHeaders: map[string]string{
						"X-Amz-Cf-Pop": "some-value",
						"Via":          "1.1"},
				},
				"HTTP_1.0": &probes.Http10ProbeData{
					Http10ResponseHeaders: map[string]string{"Server": "CloudFront"},
				},
				"CNAME": &probes.CnameProbeData{
					WasCname:       true,
					ResolvedDomain: "myhost.execute-api.us-east-2.amazonaws.com",
				},
			},
			expected: "",
		},
		{
			name: "Not Match Edge API - Cloudfront header missing in HTTP/1.0",
			probeResults: map[string]interface{}{
				"HTTP": &probes.HttpProbeData{
					IPv4:                []string{"1.2.3.4", "5.6.7.8", "9.10.11.12", "11.12.13.14"},
					HttpResponseHeaders: map[string]string{"X-Amz-Cf-Pop": "some-value", "Via": "1.1"},
				},
				"CNAME": &probes.CnameProbeData{
					WasCname:       false,
					ResolvedDomain: "not-an-api.com",
				},
				"HTTP_1.0": &probes.Http10ProbeData{
					Http10ResponseHeaders: map[string]string{"Server": "nginx"},
				},
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifiers.ClassifyEdgeAPI(tt.probeResults)
			if got != tt.expected {
				t.Errorf("ClassifyEdgeAPI() = %v, want %v", got, tt.expected)
			}
		})
	}
}
