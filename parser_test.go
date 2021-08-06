package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParser(t *testing.T) {
	// given
	conf, err := parseConfig(getTestConfig())
	require.NoError(t, err)
	file := "testdata/dummy.go"

	// when
	parser := NewParser(conf)
	parser.ParseFile(file)

	// then
	res := parser.Results
	assert.Equal(t, 4, len(res))

	expected := []Result{
		{
			File:  file,
			Line:  5,
			Name:  "internalSecret",
			Value: `"asdfasdfasdf"`,
		},
		{
			File:  file,
			Line:  9,
			Name:  "authToken",
			Value: `"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"`,
		},
		{
			File:  file,
			Line:  13,
			Name:  "TOKEN",
			Value: `"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"`,
		},
		{
			File:  file,
			Line:  17,
			Name:  "RealPostgresUri",
			Value: `"postgres://myuser:password123@blah.com:5432/mydb?sslmode=disable"`,
		},
	}

	assert.Equal(t, expected, res)
}

func getTestConfig() []byte {
	return []byte(`variableNamePattern: (?i)passwd|password|pwd|secret|token|pw|apiKey|api_key|accessKey|bearer|credentials
variableNameExclusionPattern: (?i)format
valueMatchPatterns:
  - postgres:\/\/.+:.+@.+:.+\/.+
valueExcludePatterns:
  - postgres:\/\/.+:.+@localhost:.+\/.+
  - postgres:\/\/.+:.+@127.0.0.1:.+\/.+
  - (?i)api-key
excludeTests: true`)
}
