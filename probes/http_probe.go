package probes

import (
	"crypto/tls"
	"net"
	"net/http"
	"strings"
)

type HttpProbeData struct {
	IPv4                []string
	IPv6                []string
	CertIssuer          string
	HttpResponseHeaders map[string]string
}

// HttpProbe probe function
func HttpProbe(domain string, debug bool) (interface{}, error) {
	// Create a custom transport with a TLS configuration so we can
	// turn off cert verification
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Disable TLS verification for testing
		},
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("GET", "https://"+domain, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	ipAddresses, err := net.LookupIP(resp.Request.URL.Hostname())
	if err != nil {
		return nil, err
	}

	var ipv4 []string
	var ipv6 []string
	for _, ip := range ipAddresses {
		if ip.To4() != nil {
			ipv4 = append(ipv4, ip.String())
		} else {
			ipv6 = append(ipv6, ip.String())
		}
	}

	conn, err := tls.Dial("tcp", domain+":443", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	cert := conn.ConnectionState().PeerCertificates[0]
	certIssuer := "Non-Amazon"
	if strings.Contains(cert.Subject.CommonName, ".amazonaws.com") {
		certIssuer = "Amazon"
	}

	headers := make(map[string]string)
	for key, values := range resp.Header {
		headers[key] = values[0]
	}

	if debug {
		printHeaders("HTTP Probe", headers)
		printTLSInfo(resp.TLS)
	}

	return &HttpProbeData{
		IPv4:                ipv4,
		IPv6:                ipv6,
		CertIssuer:          certIssuer,
		HttpResponseHeaders: headers,
	}, nil
}
