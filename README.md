# Credential-Detector
This simple command allows you to scan projects to detect potentially hard-coded credentials.

## Usage
`go run main.go config.go parser.go --config config.yaml --path "/home/me/myproject"`

Example output:
```
In /home/me/myproject

Line 711: secret = "Dklj34k3oi23kD"
```

## Configuration
The following configuration options are available:

```yaml
variableNamePattern: (?i)passwd|password|pwd|secret|token|pw|apiKey|api_key|accessKey|bearer|credentials
variableNameExclusionPattern: (?i)format
valueMatchPatterns:
  - postgres:\/\/.+:.+@.+:.+\/.+
valueExcludePatterns:
  - postgres:\/\/.+:.+@localhost:.+\/.+
  - postgres:\/\/.+:.+@127.0.0.1:.+\/.+
  - (?i)api-key
excludeTests: true
```

- variableNamePattern defines the regular expression for matching potentially suspicious variable names (the above value is the default)
- variableNameExclusionPattern defines the regular expression for excluding variable names that are not interesting (for example a passwordFormat pattern)
- valueMatchPatterns is a list of patterns to match potentially suspicious values, regardless of the variable name (empty by default)
- valueExcludePatterns is a list of patterns to exclude for the value (for example for test data or constants defining header names, etc)  (empty by default)
- excludeTests is a boolean flag to exclude scanning test files (defaults to false)

## Comparison to Gosec
Credential-detector is more flexible since it can be easily configured with more options than gosec and it's significantly 
faster, especially when scanning large directories. Here is a comparison using the dummy file in the testdata directory:

gosec: 
```bash
[gosec] 2021/08/06 12:16:16 Including rules: G101
[gosec] 2021/08/06 12:16:16 Excluding rules: default
[gosec] 2021/08/06 12:16:16 Import directory: /home/sfinlay/go/src/github.com/ynori7/credential-detector/testdata
[gosec] 2021/08/06 12:16:16 Checking package: testdata
[gosec] 2021/08/06 12:16:16 Checking file: /home/sfinlay/go/src/github.com/ynori7/credential-detector/testdata/dummy.go
Results:


[/home/sfinlay/go/src/github.com/ynori7/credential-detector/testdata/dummy.go:38] - G101 (CWE-798): Potential hardcoded credentials (Confidence: LOW, Severity: HIGH)
    37: 
  > 38: var PasswordFormat = "([0-9]+):(.+)"



[/home/sfinlay/go/src/github.com/ynori7/credential-detector/testdata/dummy.go:13] - G101 (CWE-798): Potential hardcoded credentials (Confidence: LOW, Severity: HIGH)
    12: const (
  > 13: 	TOKEN          = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    14: 	API_KEY_HEADER = "X-Api-Key"



[/home/sfinlay/go/src/github.com/ynori7/credential-detector/testdata/dummy.go:9] - G101 (CWE-798): Potential hardcoded credentials (Confidence: LOW, Severity: HIGH)
    8: 	anotherOkayOne = "blah"
  > 9: 	authToken      = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    10: )



Summary:
  Gosec  : dev
  Files  : 1
  Lines  : 38
  Nosec  : 0
  Issues : 3


real	0m0,108s
user	0m0,077s
sys	0m0,033s
```

credential-detector:
```bash
$ time credential-detector --config config.yaml --path testdata

In testdata/dummy.go

Line 5: internalSecret = "asdfasdfasdf"
Line 9: authToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
Line 13: TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
Line 17: RealPostgresUri = "postgres://myuser:password123@blah.com:5432/mydb?sslmode=disable"



real	0m0,004s
user	0m0,004s
sys	0m0,000s
```

credential-detector was 27 times faster, found two values which gosec missed, and excluded a false-positive which gosec reported.


## Limitations
This program is only scanning global variables and constants. It will not detect things like this:

```go
type Config {
	Secret string
}

var conf = Config{
	Secret: "blah", //struct fields are not checked
}

func main() {
	password := "blah" //local variables are not scanned
}
```