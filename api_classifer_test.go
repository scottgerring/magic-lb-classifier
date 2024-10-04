package main

import (
	"testing"
)

func TestClassifyRegionalAPI(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		ips      []string
		headers  map[string]string
		expected string
	}{
		{
			name:     "Match Regional API",
			domain:   "myhost.execute-api.us-east-2.amazonaws.com",
			ips:      []string{"1.2.3.4", "5.6.7.8"},
			headers:  map[string]string{},
			expected: "Regional API",
		},
		{
			name:     "Not Match Regional API - More than 2 IPs",
			domain:   "myhost.execute-api.us-east-2.amazonaws.com",
			ips:      []string{"1.2.3.4", "5.6.7.8", "9.10.11.12"},
			headers:  map[string]string{},
			expected: "",
		},
		{
			name:     "Not Match Regional API - CloudFront headers present",
			domain:   "myhost.execute-api.us-east-2.amazonaws.com",
			ips:      []string{"1.2.3.4", "5.6.7.8"},
			headers:  map[string]string{"X-Amz-Cf-Pop": "some-value", "Via": "1.1"},
			expected: "",
		},
		{
			name:     "Not Match Regional API - Invalid domain",
			domain:   "not-an-api.com",
			ips:      []string{"1.2.3.4"},
			headers:  map[string]string{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &DomainInfo{
				Domain:              tt.domain,
				IPv4:                tt.ips,
				HttpResponseHeaders: tt.headers,
			}
			got := classifyRegionalAPI(info)
			if got != tt.expected {
				t.Errorf("classifyRegionalAPI() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestClassifyEdgeAPI(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		ips      []string
		headers  map[string]string
		expected string
	}{
		{
			name:     "Match Edge API",
			domain:   "myhost.execute-api.us-east-2.amazonaws.com",
			ips:      []string{"1.2.3.4", "5.6.7.8", "9.10.11.12", "11.12.13.14"},
			headers:  map[string]string{"X-Amz-Cf-Pop": "some-value", "Via": "1.1"},
			expected: "Edge API",
		},
		{
			name:     "Not Match Edge API - Less than 4 IPs",
			domain:   "myhost.execute-api.us-east-2.amazonaws.com",
			ips:      []string{"1.2.3.4", "5.6.7.8"},
			headers:  map[string]string{"X-Amz-Cf-Pop": "some-value", "Via": "1.1"},
			expected: "",
		},
		{
			name:     "Not Match Edge API - CloudFront headers not present",
			domain:   "myhost.execute-api.us-east-2.amazonaws.com",
			ips:      []string{"1.2.3.4", "5.6.7.8", "9.10.11.12", "11.12.13.14"},
			headers:  map[string]string{},
			expected: "",
		},
		{
			name:     "Not Match Edge API - Invalid domain",
			domain:   "not-an-api.com",
			ips:      []string{"1.2.3.4", "5.6.7.8", "9.10.11.12", "11.12.13.14"},
			headers:  map[string]string{"X-Amz-Cf-Pop": "some-value", "Via": "1.1"},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &DomainInfo{
				Domain:              tt.domain,
				IPv4:                tt.ips,
				HttpResponseHeaders: tt.headers,
			}
			got := classifyEdgeAPI(info)
			if got != tt.expected {
				t.Errorf("classifyEdgeAPI() = %v, want %v", got, tt.expected)
			}
		})
	}
}
