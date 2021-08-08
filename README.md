# Credential-Detector
This simple command allows you to scan projects to detect potentially hard-coded credentials.

## Usage
`go run main.go config.go parser.go --config config.yaml --path "/home/me/myproject"`

Example output:
```
In /home/me/myproject

Line 711: 
secret = "Dklj34k3oi23kD"
```

## Features
This highly configurable tool scans go files, json, and yaml files, searching for potential credentials. It reports
suspiciously named go variables (excluding variables whose value indicates that it's obviously test data or some constant 
such as a header name). It additionally searches code comments and the contents of json and yaml configuration files. 

## Configuration
The following configuration options are available:

```yaml
variableNamePatterns:
  - (?i)passwd|password
  - (?i)secret
  - (?i)token
  - (?i)apiKey|api[_-]key
  - (?i)accessKey|access[_-]key
  - (?i)bearer
  - (?i)credentials
  - salt|SALT|Salt
variableNameExclusionPattern: (?i)format|tokenizer
valueMatchPatterns:
  - postgres:\/\/.+:.+@.+:.+\/.+ #postgres connection uri with password
  - eyJhbGciOiJIUzI1NiIsInR5cCI[a-zA-Z0-9_.]+ #jwt token
valueExcludePatterns:
  - postgres:\/\/.+:.+@localhost:.+\/.+ #default postgres uri for testing
  - postgres:\/\/.+:.+@127.0.0.1:.+\/.+ #default postgres uri for testing
excludeTests: true
excludeComments: false
includeJsonFiles: true
includeYamlFiles: true
disableOutputColors: false
```

Note that the above values are the defaults.

- variableNamePatterns defines the regular expressions for matching potentially suspicious variable names 
- variableNameExclusionPattern defines the regular expression for excluding variable names that are not interesting (for example a passwordFormat pattern)
- valueMatchPatterns is a list of patterns to match potentially suspicious values, regardless of the variable name 
- valueExcludePatterns is a list of patterns to exclude for the value (for example for test data or constants defining header names, etc)
- excludeTests is a boolean flag to exclude scanning test files
- excludeComments is a boolean flag to exclude scanning comments in the code 
- includeJsonFiles is a boolean flag which, when true, triggers the program to also scan json files
- includeYamlFiles is a boolean flag which, when true, triggers the program to also scan yaml files
- disableOutputColors is a boolean flag to disable colorized output when printing the results

## Comparison to Gosec
Credential-detector is more flexible since it can be easily configured with more options than gosec and it's significantly 
faster, especially when scanning large directories. Here is a comparison using the dummy file in the testdata directory:

gosec: 
```bash
$ time gosec -include=G101 testdata
[gosec] 2021/08/07 21:14:01 Including rules: G101
[gosec] 2021/08/07 21:14:01 Excluding rules: default
[gosec] 2021/08/07 21:14:01 Import directory: /home/sfinlay/go/src/github.com/ynori7/credential-detector/testdata
[gosec] 2021/08/07 21:14:01 Checking package: testdata
[gosec] 2021/08/07 21:14:01 Checking file: /home/sfinlay/go/src/github.com/ynori7/credential-detector/testdata/dummy.go
Results:


[/home/sfinlay/go/src/github.com/ynori7/credential-detector/testdata/dummy.go:43] - G101 (CWE-798): Potential hardcoded credentials (Confidence: LOW, Severity: HIGH)
    42: 
  > 43: var PasswordFormat = "([0-9]+):(.+)"
    44: 



[/home/sfinlay/go/src/github.com/ynori7/credential-detector/testdata/dummy.go:9] - G101 (CWE-798): Potential hardcoded credentials (Confidence: LOW, Severity: HIGH)
    8: 	anotherOkayOne = "blah"
  > 9: 	authToken      = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    10: )



Summary:
  Gosec  : dev
  Files  : 1
  Lines  : 53
  Nosec  : 0
  Issues : 2


real	0m0,116s
user	0m0,112s
sys	0m0,035s
```

credential-detector:
```bash
In testdata/dummy.go

Line 5: 
internalSecret = "asdfasdfasdf"

Line 9: 
authToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

Line 13: 
AccessCode = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

Line 17: 
RealPostgresUri = "postgres://myuser:password123@blah.com:5432/mydb?sslmode=disable"

Line 20: 
/*
Multiline comment
postgres://myuser:password123@localhost:5432/mydb?sslmode=disable
*/

Line 47: 
blahToken = "password"

Line 51: 
// this is a local comment
// "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"




In testdata/dummy.json

JSON Variable: 
"apiKey": "aslkdjflkjwe#Kjkjoi3"

JSON Variable: 
"secret": "23423Ksk3s"

JSON List Item:
"stuff2": [
...
"postgres://myuser:password123@localhost:5432/mydb?sslmode=disable",
...
]

JSON Variable: 
"token": "lkaskjlklejer#4"




In testdata/dummy.yaml

YAML Variable: 
"accessKey": "2342342kjasdre"

YAML List Item:
"args": [
...
- "postgres://myuser:password123@localhost:5432/mydb?sslmode=disable",
...
]


real	0m0,008s
user	0m0,000s
sys	0m0,010s
```

credential-detector was 16 times faster, found six values which gosec missed in go code, included six values from json 
and yaml files which gosec did not check, and excluded a false-positive which gosec reported.


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
