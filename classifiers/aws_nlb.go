package classifiers

import (
	"magic-lb-classifier/probes"
	"regexp"
)

// Regular expression for matching API Gateway hostnames
var nlbRegex = regexp.MustCompile(`^[^.]+\.elb\.[^.]+\.amazonaws.com$`)

// Classifier for NLB
func ClassifyNLB(probeResults map[string]interface{}) string {
	httpData, ok := probeResults["HTTP"].(probes.HttpProbeData)
	if !ok {
		return ""
	}

	cnameData, ok := probeResults["CNAME"].(probes.CnameProbeData)
	if !nlbRegex.MatchString(cnameData.ResolvedDomain) {
		return ""
	}

	if len(httpData.IPv6) > 0 {
		return "NLB (IPv6-enabled)"
	}

	return "NLB"
}
