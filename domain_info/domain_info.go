package domain_info

// Info we need for classification. Will extend as we add more classifiers!
type DomainInfo struct {
	Domain                string            // Resolved domain name
	OriginalDomain        string            // Original input domain name
	IPv4                  []string          // List of IPv4 addresses
	IPv6                  []string          // List of IPv6 addresses
	CertIssuer            string            // Certificate Issuer (Amazon vs. non-Amazon)
	HttpResponseHeaders   map[string]string // Map of HTTP response headers
	Http10ResponseHeaders map[string]string // Map of HTTP response headers when we force a bad HTTP/1.0 request
}
