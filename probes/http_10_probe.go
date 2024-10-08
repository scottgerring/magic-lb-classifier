package probes

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
)

// Http10ProbeData contains headers returned by the HTTP/1.0 probe
type Http10ProbeData struct {
	Http10ResponseHeaders map[string]string
}

// Http10Probe Runs a HTTP/1.0 probe without a `Host` header.
func Http10Probe(domain string, debug bool) (interface{}, error) {
	headers, err := sendHttpRequest(domain)
	if err != nil {
		return nil, err
	}
	return &Http10ProbeData{
		Http10ResponseHeaders: headers,
	}, nil
}

func sendHttpRequest(domain string) (map[string]string, error) {
	address := domain + ":443"
	conn, err := tls.Dial("tcp", address, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, fmt.Errorf("failed to establish connection: %v", err)
	}
	defer conn.Close()

	request := "GET / HTTP/1.0\r\n\r\n"
	_, err = conn.Write([]byte(request))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}
	defer resp.Body.Close()

	headers := make(map[string]string)
	for key, values := range resp.Header {
		headers[key] = strings.Join(values, ", ")
	}

	return headers, nil
}
