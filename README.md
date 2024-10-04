# Magic API Classifier

This project is a Golang-based experiment designed to identify the cloud-based load balancer sitting behind a given
hostname. This is a toy / learning-experience sort of thing, and not at all serious, production grade code.

At the moment it can pick out AWS load balancers (ALB/NLB/API Gateway), primarily by assuming things about their hostnames
and their use of particular TLS versions. In the future I'd love to see if we can do something more fundamental - looking
at BGP ownership of the endpoints, maybe some TCP fingerprinting. We'll see!

```bash
go run api_classifier.go myapi.com --debug
```





