package classifiers

// Classifier function types
type ClassifierFunc func(probeResults map[string]interface{}) string

// List of classifiers
var classifierFuncs = []ClassifierFunc{
	ClassifyRegionalAPI,
	ClassifyEdgeAPI,
	ClassifyALB,
	ClassifyNLB,
}

// ClassifyDomain classifies the given domain probe results as a particular load balancer
func ClassifyDomain(probeResults map[string]interface{}) string {

	for _, classifierFunc := range classifierFuncs {
		classification := classifierFunc(probeResults)
		if classification != "" {
			return classification
		}
	}

	return "Unknown"
}
