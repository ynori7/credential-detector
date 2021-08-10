package parser

import (
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
variableNameExclusionPattern: (?i)format|tokenizer|secretName|Error$
valueMatchPatterns:
  - postgres:\/\/.+:.+@.+:.+\/.+ #postgres connection uri with password
  - eyJhbGciOiJIUzI1NiIsInR5cCI[a-zA-Z0-9_.]+ #jwt token
valueExcludePatterns:
  - postgres:\/\/.+:.+@localhost:.+\/.+ #default postgres uri for testing
  - postgres:\/\/.+:.+@127.0.0.1:.+\/.+ #default postgres uri for testing
  - postgres:\/\/postgres:postgres@postgres:.+\/.+ #default postgres uri for testing
  - (?i)^test$|^postgres$|^root$|^foobar$|^example$|^changeme$|^default$ #common dummy values
  - (?i)^true$|^false$
  - (?i)^bearer$
excludeTests: true
testDirectories:
  - test
  - testdata
excludeComments: false
scanTypes: 
  - go
  - yaml
  - json
  - properties
disableOutputColors: false
verbose: false`)
}
