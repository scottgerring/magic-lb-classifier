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
			expected: "API Gateway: Regional API",
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
			expected: "API Gateway: Edge API",
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

func TestClassifyALB(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		ipv4     []string
		ipv6     []string
		expected string
	}{
		{
			name:     "Match ALB with IPv4",
			domain:   "myloadbalancer-1234567890.us-east-1.elb.amazonaws.com",
			ipv4:     []string{"1.2.3.4"},
			ipv6:     []string{},
			expected: "ALB",
		},
		{
			name:     "Match ALB with IPv6",
			domain:   "myloadbalancer-1234567890.us-east-1.elb.amazonaws.com",
			ipv4:     []string{},
			ipv6:     []string{"2606:4700:4700::1111"},
			expected: "ALB (IPv6-enabled)",
		},
		{
			name:     "Not Match ALB - Invalid domain",
			domain:   "not-an-alb.com",
			ipv4:     []string{"1.2.3.4"},
			ipv6:     []string{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &DomainInfo{
				Domain: tt.domain,
				IPv4:   tt.ipv4,
				IPv6:   tt.ipv6,
			}
			got := classifyALB(info)
			if got != tt.expected {
				t.Errorf("classifyALB() = %v, want %v", got, tt.expected)
			}
		})
	}
}
