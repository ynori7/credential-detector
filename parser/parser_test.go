package parser

import (
	"github.com/stretchr/testify/require"
	"github.com/ynori7/credential-detector/config"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_getFileNameAndExtension(t *testing.T) {
	testcases := map[string]struct {
		expectedName string
		expectedExt  string
	}{
		"/etc/passwd": {
			expectedName: "passwd",
			expectedExt:  "",
		},
		"/home/blah/test.txt": {
			expectedName: "test",
			expectedExt:  ".txt",
		},
		"/home/blah/.bash_rc": {
			expectedName: "",
			expectedExt:  ".bash_rc",
		},
		"/home/blah/.test.swp": {
			expectedName: ".test",
			expectedExt:  ".swp",
		},
	}

	for path, expected := range testcases {
		actualName, actualExt := getFileNameAndExtension(path)

		assert.Equal(t, expected.expectedName, actualName, path)
		assert.Equal(t, expected.expectedExt, actualExt, path)
	}
}

func Test_isPossiblyCredentialsVariable(t *testing.T) {
	testcases := map[string]struct {
		varName  string
		varVal   string
		expected bool
	}{
		"Not credentials": {
			varName:  "x",
			varVal:   "5",
			expected: false,
		},
		"Name looks like credentials": {
			varName:  "blahPassword",
			varVal:   "5asdfasdfasdf",
			expected: true,
		},
		"Name looks like credentials, but excluded": {
			varName:  "blahPasswordFormat",
			varVal:   "asdfasdfasdf5",
			expected: false,
		},
		"Name looks like credentials but value too short": {
			varName:  "blahPassword",
			varVal:   "5",
			expected: false,
		},
		"Name looks like credentials, but value is excluded": {
			varName:  "blahPassword",
			varVal:   "test",
			expected: false,
		},
		"Value looks like credentials": {
			varName:  "test",
			varVal:   "postgres://myuser:password123@blah.com:5432/mydb?sslmode=disable",
			expected: true,
		},
		"Name looks like credentials, but value matches name": {
			varName:  "API_KEY",
			varVal:   "X-API-KEY",
			expected: false,
		},
	}

	conf, err := config.ParseConfig(getTestConfig())
	require.NoError(t, err)
	parser := NewParser(conf)

	for testname, testdata := range testcases {
		actual := parser.isPossiblyCredentialsVariable(testdata.varName, testdata.varVal)

		assert.Equal(t, testdata.expected, actual, testname)
	}
}

func Test_isPossiblyCredentialValue(t *testing.T) {
	testcases := map[string]struct {
		varVal   string
		expected bool
	}{
		"Value is excluded": {
			varVal:   "test",
			expected: false,
		},
		"Value looks like credentials": {
			varVal:   "postgres://myuser:password123@blah.com:5432/mydb?sslmode=disable",
			expected: true,
		},
		"Not credentials": {
			varVal:   "blah",
			expected: false,
		},
	}

	conf, err := config.ParseConfig(getTestConfig())
	require.NoError(t, err)
	parser := NewParser(conf)

	for testname, testdata := range testcases {
		actual := parser.isPossiblyCredentialValue(testdata.varVal)

		assert.Equal(t, testdata.expected, actual, testname)
	}
}

func Test_Scan(t *testing.T) {
	conf, err := config.ParseConfig(getTestConfig())
	require.NoError(t, err)
	parser := NewParser(conf)

	err = parser.Scan("../testdata/")
	require.NoError(t, err)
	assert.Equal(t, 31, len(parser.Results))
}

func parseFileForTest(parser *Parser, filepath string) {
	parser.ParseFile(filepath)
	close(parser.resultChan) //tell the result builder we're done
	<-parser.resultBuildDone //wait till result builder is done
}

func getTestConfig() []byte {
	return []byte(`variableNamePatterns:
  - (?i)passwd|password
  - (?i)secret
  - (?i)token
  - (?i)apiKey|api[_-]key
  - (?i)accessKey|access[_-]key
  - (?i)bearer
  - (?i)credentials
  - salt|SALT|Salt
  - (?i)signature
variableNameExclusionPattern: (?i)format|tokenizer|secretName|Error$|passwordPolicy|tokens$|tokenPolicy|[,\s#+*^|}{'"\[\]]
xmlAttributeNameExclusionPattern: (?i)token #values that tend to have a different meaning for xml
valueMatchPatterns:
  - postgres:\/\/.+:.+@.+:.+\/.+ #postgres connection uri with password
  - eyJhbGciOiJIUzI1NiIsInR5cCI[a-zA-Z0-9_.]+ #jwt token
  - ^\$2[ayb]\$.{56}$  #bcrypt hash
  - (A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16} #AWS client id
  - SG\.[\w_-]{16,32}\.[\w_-]{16,64} #SendGrid API key
  - amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12} #Amazon MMS Key
  - (?i)(facebook|fb)(.{0,20})?(?-i)['\"][0-9a-f]{32}['\"] #Facebook Secret
  - (?i)(facebook|fb)(.{0,20})?['\"][0-9]{13,17}['\"] #Facebook client id
  - (?i)twitter(.{0,20})?['\"][0-9a-z]{35,44}['\"] #Twitter secret
  - (?i)twitter(.{0,20})?['\"][0-9a-z]{18,25}['\"] #Twitter client id
  - (?i)github(.{0,20})?(?-i)['\"][0-9a-zA-Z]{35,40}['\"] #Github Secret
  - (?i)linkedin(.{0,20})?(?-i)['\"][0-9a-z]{12}['\"] #LinkedIn client id
  - (?i)linkedin(.{0,20})?['\"][0-9a-z]{16}['\"] #LinkedIn secret
  - xox[baprs]-([0-9a-zA-Z]{10,48})? #Slack
  - -----BEGIN ((EC|PGP|DSA|RSA|OPENSSH) )?PRIVATE KEY( BLOCK)?----- #Private Key
  - AIza[0-9A-Za-z\\-_]{35} #Google API Key
  - (?i)heroku(.{0,20})?['"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['"] #Heroku Key
  - (?i)(mailchimp|mc)(.{0,20})?['"][0-9a-f]{32}-us[0-9]{1,2}['"] #MailChip Key
  - (?i)(mailgun|mg)(.{0,20})?['"][0-9a-z]{32}['"] #MailGut Key
  - https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8}\/[a-zA-Z0-9_]{24} #Slack WebHook
  - (?i)twilio(.{0,20})?['\"][0-9a-f]{32}['\"] #Twilio Key
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
excludeTests: false
testDirectories:
  - test
  - testdata
  - example
  - data
excludeComments: false
scanTypes: #possible values are go|yaml|json|properties|privatekey|xml|php
  - go
  - yaml
  - json
  - properties
  - privatekey
  - xml
  - php
  - generic
genericFileExtensions:
  - txt
  - java
  - cpp
  - c
  - py
  - md
  - js
  - html
disableOutputColors: false
verbose: false`)
}
