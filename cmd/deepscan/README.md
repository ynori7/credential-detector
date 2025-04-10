# deepscan
Deepscan is a command that will iterate over every commit to a repo and check for the presence of 
hardcoded credentials so that you can revoke previously leaked credentials.

### Usage
```
go run cmd/deepscan/main.go --config /path/to/credential-config.yaml --path /path/to/repo
```
### Notes
Currently it's very basic, simply brute-force scanning every commit and dumping the results. In the
future it should store the list of results to avoid printing the same result over and over.