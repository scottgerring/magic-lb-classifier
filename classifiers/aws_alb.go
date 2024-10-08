package classifiers

import (
	"magic-lb-classifier/probes"
	"regexp"
)

var albRegex = regexp.MustCompile(`^[^.]+\.[^.]+\.elb\.amazonaws.com$`)

// Classifier for ALB
func ClassifyALB(probeResults map[string]interface{}) string {
	httpData, ok := probeResults["HTTP"].(*probes.HttpProbeData)
	if !ok {
		return ""
	}

	cnameData, ok := probeResults["CNAME"].(*probes.CnameProbeData)
	if !ok {
		return ""
	}
	if !albRegex.MatchString(cnameData.ResolvedDomain) {
		return ""
	}

	if len(httpData.IPv6) > 0 {
		return "ALB (IPv6-enabled)"
	}
	return "ALB"
}
