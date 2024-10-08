package probes

import (
	"log"
)

type ProbeFunc func(domain string, debug bool) (interface{}, error)

// All our probes go here
var probeFuncMap map[string]ProbeFunc

func init() {
	probeFuncMap = map[string]ProbeFunc{
		"HTTP":     HttpProbe,
		"Http_1.0": Http10Probe,
		"CNAME":    CnameProbe,
	}
}

// ProbeDomain function that uses the global map of probe functions
func ProbeDomain(domain string, debug bool) (map[string]interface{}, error) {
	// Initialize the map that will hold the probe results
	results := make(map[string]interface{})

	// Iterate over all registered probes and execute each one
	for probeName, probeFunc := range probeFuncMap {
		// Execute the probe function, passing the domain
		data, err := probeFunc(domain, debug)
		if err != nil {
			// Handle the error appropriately, e.g., log it and continue with other probes
			log.Printf("Error running probe %s: %v", probeName, err)
			continue
		}
		// Store the result using the probe name as the key
		results[probeName] = data
	}

	return results, nil
}
