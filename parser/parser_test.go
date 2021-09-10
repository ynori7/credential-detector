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
disableOutputColors: false
verbose: false`)
}
