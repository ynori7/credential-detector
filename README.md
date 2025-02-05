# Credential-Detector [![Go Report Card](https://goreportcard.com/badge/ynori7/credential-detector)](https://goreportcard.com/report/github.com/ynori7/credential-detector) [![Build Status](https://travis-ci.org/ynori7/credential-detector.svg?branch=master)](https://travis-ci.com/github/ynori7/credential-detector)
This simple command allows you to scan projects to detect potentially hard-coded credentials.

Hard-coded credentials are authentication data such as passwords, API keys, authorization tokens,
or private keys which have been embedded directly into the source code or static configuration files rather
than obtaining them from an external source or injecting them upon deployment/runtime. This common practice
tremendously increases the possibility for malicious users to guess passwords and obtain access to your systems.

With this tool, it becomes an easy task to locate credentials which were mistakenly (or naively) committed to
your repositories so that they can be revoked and replaced with more secure practices. 

Further reading:
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [OWASP Use of hard-coded passwords](https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password)


## Installation
```bash
go install github.com/ynori7/credential-detector
```

## Usage
`go run main.go --config config.yaml --path "/home/me/myproject"`

Example output:
```
In /home/me/myproject

Line 711: 
secret = "Dklj34k3oi23kD"
```

If the config flag is omitted, default configuration will be used.

For convenience, there is also a script called [detect-credentials-in-github-org.sh](scripts/detect-credentials-in-github-org.sh) which 
can be used to fetch all repos in your Github organization to scan them.

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
- Generic text files

## Configuration
When running the credential detector, it is possible to provide an optional `--root_config`, which supplies the base 
configuration and a `--config` which defines any additions/modifications to the base. 

The following configuration options are available (these values are simplified examples. See config/default_config.yaml for the full defaults):

```yaml
variableNamePatterns:
  - (?i)passwd|password
  - (?i)secret
  - (?i)token
  - (?i)apiKey|api[_-]key
variableNameExclusionPattern: (?i)format|tokenizer|secretName
xmlAttributeNameExclusionPattern: (?i)token #values that tend to have a different meaning for xml
valueMatchPatterns:
  - name: Postgres URI
    pattern: postgres:\/\/.+:.+@.+:.+\/.+

  - name: JWT Token
    pattern: eyJhbGciOiJIUzI1NiIsInR5cCI[a-zA-Z0-9_.]+
variableValueExcludePatterns:
  - (?i)^test$|password|^postgres$|^root$|^foobar$|^example$|^changeme$|^default$|^master$ #common dummy values
fullTextValueExcludePatterns:
  - postgres:\/\/.+:.+@localhost:.+\/.+ #default postgres uri for testing
  - postgres:\/\/.+:.+@127.0.0.1:.+\/.+ #default postgres uri for testing
  - postgres:\/\/postgres:postgres@postgres:.+\/.+ #default postgres uri for testing
minPasswordLength: 6 #don't consider anything shorter than this as a possible credential
excludeTests: true
testDirectories:
  - test
ignoreFiles: #files or directories to skip
  - vendor
excludeComments: false
scanTypes: #possible values are go|yaml|json|properties|privatekey|xml|php
  - go
  - yaml
  - json
  - properties
  - privatekey
  - xml
  - php
  - bash
  - generic
  - generic_code
genericFileExtensions:
  - txt
  - md
  - html
genericCodeFileExtensions:
  - java
  - swift
  - cpp
disableOutputColors: false
verbose: false
```

Note that the above values are the defaults.

|Config Option|Description|Values|
|-------------|-----------|------|
|variableNamePatterns|The regular expressions for matching potentially suspicious variable names|List of regular expressions| 
|variableNameExclusionPattern|The regular expression for excluding variable names that are not interesting (for example a passwordFormat pattern)|A regular expression|
|xmlAttributeNameExclusionPattern|The regular expression for excluding xml attributes since XML often describes a model rather than containing the data.|A regular expression|
|valueMatchPatterns|A list of patterns to match potentially suspicious values, regardless of the variable name|List of objects containing a name and regular expression|
|variableValueExcludePatterns|A list of patterns to exclude for the value (for example for test data or constants defining header names, etc). These are only applied if we're looking at a variable assignment.|List of regular expressions|
|fullTextValueExcludePatterns|A list of patterns to exclude for the value (for example for test data or constants defining header names, etc). These are applied for variable assignments and general full text scans.|List of regular expressions|
|excludeTests|A boolean flag to exclude scanning test files|true or false|
|testDirectories|A list of directory names which are considered test data only|A list of strings|
|ignoreFiles|A list of directory or file names which should be ignored|A list of strings|
|excludeComments|A boolean flag to exclude scanning comments in the code |true or false|
|scanTypes|A list of file types which should be scanned|A list of strings with values: go, json, yaml, properties, privatekey, xml, php, bash, generic, or generic_code|
|genericFileExtensions|A list of file extensions which can be parsed as plaintext. These will be scanned for possible value matches|
|genericCodeFileExtensions|A list of file extensions which can be parsed as generic code.|
|disableOutputColors|A boolean flag to disable colorized output when printing the results|true or false|
|verbose|A boolean flag which toggles the output of warning messages which occur while parsing specific files|true or false|

The configuration from config/default_config.yaml is the default root configuration. If the `--config` flag is provided,
the values for the boolean fields and scanTypes will be take from this config, and the values for minPasswordLength and 
variableNameExclusionPattern will be taken if non-empty. For all other list attributes, the values from the supplied
configuration will be appended to the root.

## Comparison to Gosec
Credential-detector is more flexible since it can be easily configured with more options than gosec and it's significantly 
faster, especially when scanning large directories. Here is a comparison using the dummy.go file in the testdata directory:

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
RealPostgresUri = "postgres://myuser:pas2sword123@blah.com:5432/mydb?sslmode=disable"

Line 20: 
Possible Postgres URI
/*
Multiline comment
postgres://myuser:pas2sword123@somepostgresdb:5432/mydb?sslmode=disable
*/

Line 47: 
blahToken = "pas2sword123"

Line 51: 
Possible JWT Token
// this is a local comment
// "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

Line 54: 
Possible AWS Client ID
NewStaticCredentials("AKIAYTHMXXXGSVYYYWE6", "rP22kgSajDwOyWVU/iiii1UEdJk333QUbxwtiVCe")

real	0m0,008s
user	0m0,000s
sys	0m0,010s
```

credential-detector was 16 times faster, found seven values which gosec missed in go code, and additionally found 24 results in
 other files which gosec did not check, and excluded a false-positive which gosec reported.

## Comparison to Github Advanced Security and Spectral
Tools like GHAS and Spectral are oriented around pattern-recognition only. This means that they search for well-known
credential types which have a recognizable pattern like AWS client IDs or Google API keys. The limitation with that approach
is that it can only detect well-known credentials and not custom ones like internal API keys or user passwords, etc. 

This project differs in that it detects credentials through context in addition to patterns. It looks not only at how
a value appears (if it matches some pattern), but how it seems to be used (e.g. based on the name of the variable it's assigned to).
This makes credential-detector more robust because it can detect all sorts of credentials and secrets and not only well-known
types.

GHAS and similar tools like GitGuardian only detected two credentials in the test files of this repository (the dummy 
SendGrid API Key and the dummy AWS Client ID) compared to the 32 results detected by credential-detector.

## Usage as a library
The credential scanner can also be used as a library like so:

```go
package main

import (
	"log"

	"github.com/ynori7/credential-detector/config"
	"github.com/ynori7/credential-detector/parser"
)

func main() {
	//Specify the configuration file paths. Use empty string as root config to use default root
	conf, err := config.LoadConfig("myconfig.yaml", "myrootconfig.yaml")
	if err != nil {
		log.Fatal(err.Error())
	}

	p := parser.NewParser(conf)
	if err := p.Scan("/myScanPath"); err != nil {
		log.Fatal(err.Error())
	}

	//results are in p.Results
}
```

## Limitations
The Go scanner is only scanning global variables and constants. It will not detect things like this:

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

XML tends to have a lot of false positives due to the fact that it often describes a model without actually containing 
the data like so:

```xml
<element id="password" label="Password" type="password">
    <validations>
        <validation type="passwordlength">
        ....
```
