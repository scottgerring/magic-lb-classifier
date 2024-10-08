package main

import (
	"fmt"
	"log"
	"magic-lb-classifier/classifiers"
	"magic-lb-classifier/probes"
	"os"
)

// Main function
func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run api_classifier.go <domain-name> [--debug]")
		return
	}
	domain := os.Args[1]
	debug := len(os.Args) > 2 && os.Args[2] == "--debug"

	// Probe the domain
	probeResults, err := probes.ProbeDomain(domain, debug)
	if err != nil {
		log.Fatal(err)
	}

	// Run classifiers using the probe results
	classification := classifiers.ClassifyDomain(probeResults)
	fmt.Printf("Classification: %s\n", classification)
}
