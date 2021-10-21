package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ynori7/credential-detector/config"
)

func Test_isParsableGoFile(t *testing.T) {
	testcases := map[string]struct {
		path         string
		expected     bool
		includeTests bool
	}{
		"No extension": {
			path:         "/etc/passwd",
			expected:     false,
			includeTests: true,
		},
		"No extension, name is go": {
			path:         "/etc/go",
			expected:     false,
			includeTests: true,
		},
		"Not go extension": {
			path:         "/home/blah/test.txt",
			expected:     false,
			includeTests: true,
		},
		"Not go extension, hidden file": {
			path:         "/home/blah/.test.swp",
			expected:     false,
			includeTests: true,
		},
		"Go extension, hidden file": {
			path:         "/home/blah/.blah.go",
			expected:     true,
			includeTests: true,
		},
		"Go extension": {
			path:         "/home/blah/blah.go",
			expected:     true,
			includeTests: true,
		},
		"Go test": {
			path:         "/home/blah/blah_test.go",
			expected:     true,
			includeTests: true,
		},
		"Go test, tests excluded": {
			path:         "/home/blah/blah_test.go",
			expected:     false,
			includeTests: false,
		},
		"Go file named test, tests excluded": {
			path:         "/home/blah/test.go",
			expected:     true,
			includeTests: false,
		},
	}

	for testcase, testdata := range testcases {
		conf, err := config.ParseConfig(getTestConfig())
		require.NoError(t, err, testcase)
		conf.ExcludeTests = !testdata.includeTests

		parser := NewParser(conf)
		actual := parser.isParsableGoFile(testdata.path)

		assert.Equal(t, testdata.expected, actual, testcase)
	}
}

func TestParser_Go(t *testing.T) {
	// given
	conf, err := config.ParseConfig(getTestConfig())
	require.NoError(t, err)
	file := "../testdata/dummy.go"

	expected := []Result{
		{
			File:  file,
			Type:  TypeGoVariable,
			Line:  5,
			Name:  "internalSecret",
			Value: `"asdfasdfasdf"`,
		},
		{
			File:  file,
			Type:  TypeGoVariable,
			Line:  9,
			Name:  "authToken",
			Value: `"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"`,
		},
		{
			File:  file,
			Type:  TypeGoVariable,
			Line:  13,
			Name:  "AccessCode",
			Value: `"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"`,
		},
		{
			File:  file,
			Type:  TypeGoVariable,
			Line:  17,
			Name:  "RealPostgresUri",
			Value: `"postgres://myuser:password123@blah.com:5432/mydb?sslmode=disable"`,
		},
		{
			File:  file,
			Type:  TypeGoVariable,
			Line:  47,
			Name:  "blahToken",
			Value: `"password"`,
		},
		{
			File: file,
			Type: TypeGoComment,
			Line: 20,
			Name: "",
			Value: `/*
Multiline comment
postgres://myuser:password123@somepostgresdb:5432/mydb?sslmode=disable
*/`,
		},
		{
			File: file,
			Type: TypeGoComment,
			Line: 51,
			Name: "",
			Value: `// this is a local comment
// "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"`,
		},
		{
			File:  file,
			Type:  TypeGoOther,
			Line:  54,
			Name:  "",
			Value: `NewStaticCredentials("AKIAYTHMXXXGSVYYYWE6", "rP22kgSajDwOyWVU/iiii1UEdJk333QUbxwtiVCe")`,
		},
	}

	// when
	parser := NewParser(conf)
	parser.ParseFile(file)

	// then
	res := parser.Results
	assert.Equal(t, len(expected), len(res))
	assert.Equal(t, expected, res)
}
