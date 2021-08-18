# Credential-Detector [![Go Report Card](https://goreportcard.com/badge/ynori7/credential-detector)](https://goreportcard.com/report/github.com/ynori7/credential-detector) [![Build Status](https://travis-ci.org/ynori7/credential-detector.svg?branch=master)](https://travis-ci.com/github/ynori7/credential-detector)
This simple command allows you to scan projects to detect potentially hard-coded credentials.

Hard-coded credentials are authentication data such as passwords, API keys, authorization tokens,
or private keys which have been embedded directory into the source code or static configuration files rather
than obtaining them from an external source or injecting them upon deployment/runtime. This common practice
tremendously increases the possibility for malicious users to guess passwords and obtain access to your systems.

With this tool, it becomes an easy task to locate credentials which were mistakenly (or naively) committed to
your repositories so that they can be revoked and replaced with more secure practices. 

## Installation
```bash
go install github.com/ynori7/credential-detector
```

## Usage
`go run main.go config.go parser.go --config config.yaml --path "/home/me/myproject"`

Example output:
```
In /home/me/myproject

Line 711: 
secret = "Dklj34k3oi23kD"
```

If the config flag is omitted, default configuration will be used.

## Features
This highly configurable tool scans a multitude of file types searching for potential credentials. It reports
suspiciously named variables (excluding variables whose value indicates that it's obviously test data or some constant 
such as a header name). It additionally searches code comments and various configuration files. The scanner
can also detect private key and certificate files.

Credential-detector can scan:

- Go code
- JSON files
- YAML files
- Properties files
- Private key / certificate files
- XML files
- PHP code

## Configuration
When running the credential detector, it is possible to provide an optional `--root_config`, which supplies the base 
configuration and a `--config` which defines any additions/modifications to the base. 

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
  - (?i)signature
variableNameExclusionPattern: (?i)format|tokenizer|secretName|Error$|passwordPolicy|tokens$|tokenPolicy|[,\s#+*^|}{'"\[\]]|regex
valueMatchPatterns:
  - postgres:\/\/.+:.+@.+:.+\/.+ #postgres connection uri with password
  - eyJhbGciOiJIUzI1NiIsInR5cCI[a-zA-Z0-9_.]+ #jwt token
valueExcludePatterns:
  - postgres:\/\/.+:.+@localhost:.+\/.+ #default postgres uri for testing
  - postgres:\/\/.+:.+@127.0.0.1:.+\/.+ #default postgres uri for testing
  - postgres:\/\/postgres:postgres@postgres:.+\/.+ #default postgres uri for testing
  - (?i)^test$|^postgres$|^root$|^foobar$|^example$|^changeme$|^default$|^master$ #common dummy values
  - (?i)^string$|^integer$|^number$|^boolean$|^xsd:.+|^literal$
  - (?i)^true$|^false$
  - (?i)^bearer$|^Authorization$
  - bootstrapper
  - \${.+\} #typically for values injected at build time
  - (?i){{.*}}
minPasswordLength: 6 #don't consider anything shorter than this as a possible credential
excludeTests: true
testDirectories:
  - test
  - tests
  - testdata
  - example
  - data
ignoreFiles: #files or directories to skip
  - vendor
  - .git
  - .idea
excludeComments: false
scanTypes: #possible values are go|yaml|json|properties|privatekey|xml|php
  - go
  - yaml
  - json
  - properties
  - privatekey
  - xml
  - php
disableOutputColors: false
verbose: false
```

Note that the above values are the defaults.

|Config Option|Description|Values|
|-------------|-----------|------|
|variableNamePatterns|The regular expressions for matching potentially suspicious variable names|List of regular expressions| 
|variableNameExclusionPattern|The regular expression for excluding variable names that are not interesting (for example a passwordFormat pattern)|A regular expression|
|valueMatchPatterns|A list of patterns to match potentially suspicious values, regardless of the variable name|List of regular expressions|
|valueExcludePatterns|A list of patterns to exclude for the value (for example for test data or constants defining header names, etc)|List of regular expressions|
|excludeTests|A boolean flag to exclude scanning test files|true or false|
|testDirectories|A list of directory names which are considered test data only|A list of strings|
|ignoreFiles|A list of directory or file names which should be ignored|A list of strings|
|excludeComments|A boolean flag to exclude scanning comments in the code |true or false|
|scanTypes|A list of file types which should be scanned|A list of strings with values: go, json, yaml, properties, privatekey, xml, or php|
|disableOutputColors|A boolean flag to disable colorized output when printing the results|true or false|
|verbose|A boolean flag which toggles the output of warning messages which occur while parsing specific files|true or false|

The configuration from config/default_config.yaml is the default root configuration. If the `--config` flag is provided,
the values for the boolean fields and scanTypes will be take from this config, and the values for minPasswordLength and 
variableNameExclusionPattern will be taken if non-empty. For all other list attributes, the values from the supplied
configuration will be appended to the root.

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
