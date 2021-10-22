package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ynori7/credential-detector/config"
)

func Test_isParsablePhpFile(t *testing.T) {
	testcases := map[string]struct {
		path     string
		expected bool
	}{
		"No extension": {
			path:     "/etc/passwd",
			expected: false,
		},
		"No extension, name is php": {
			path:     "/etc/php",
			expected: false,
		},
		"Not php extension": {
			path:     "/home/blah/test.txt",
			expected: false,
		},
		"Not php extension, hidden file": {
			path:     "/home/blah/.test.swp",
			expected: false,
		},
		"Php extension, hidden file": {
			path:     "/home/blah/.blah.php",
			expected: true,
		},
		"No extension, hidden file": {
			path:     "/home/blah/.env",
			expected: false,
		},
		"Php extension": {
			path:     "/home/blah/blah.php",
			expected: true,
		},
	}

	conf, err := config.ParseConfig(getTestConfig())
	require.NoError(t, err)
	parser := NewParser(conf)

	for testcase, testdata := range testcases {
		actual := parser.isParsablePhpFile(testdata.path)

		assert.Equal(t, testdata.expected, actual, testcase)
	}
}

func TestParser_Php(t *testing.T) {
	// given
	conf, err := config.ParseConfig(getTestConfig())
	require.NoError(t, err)
	file := "../testdata/dummy.php"
	expected := []Result{
		{
			File:  file,
			Type:  TypePHPVariable,
			Line:  11,
			Name:  "$apiKey",
			Value: `"asfwe3#eswer"`,
		},
		{
			File: file,
			Type: TypePHPHeredoc,
			Line: 13,
			Name: "$appToken",
			Value: `<<<EOF
KJEKJEKJeke
eke
ekwekwekljwer
EOF`,
		},
		{
			File:  file,
			Type:  TypePHPVariable,
			Line:  22,
			Name:  "$myPassword2",
			Value: `"blahblah" . $t`,
		},
		{
			File:  file,
			Type:  TypePHPConstant,
			Line:  26,
			Name:  "const API_KEY",
			Value: `'askljlkwejrwe'`,
		},
		{
			File:  file,
			Type:  TypePHPConstant,
			Line:  31,
			Name:  "const INTERNAL_API_KEY",
			Value: `'kiu#pKJSDK;LE'`,
		},
		{
			File:  file,
			Type:  TypePHPComment,
			Line:  33,
			Name:  "",
			Value: `// "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"`,
		},
		{
			File:  file,
			Type:  TypePHPVariable,
			Line:  35,
			Name:  "private $password",
			Value: `"woieruwkljlekjrlkwjer"`,
		},
		{
			File:  file,
			Type:  TypePHPOther,
			Line:  38,
			Name:  "",
			Value: `NewStaticCredentials("AKIAYTHMXXXGSVYYYWE6", "rP22kgSajDwOyWVU/iiii1UEdJk333QUbxwtiVCe");`,
		},
		{
			File: file,
			Type: TypePHPComment,
			Line: 42,
			Name: "",
			Value: `/*
* This is a multiline comment
* it contains postgres://myuser:password123@somepostgresdb:5432/mydb?sslmode=disable
*/`,
		},
	}

	// when
	parser := NewParser(conf)
	parseFileForTest(parser, file)

	// then
	res := parser.Results
	assert.Equal(t, len(expected), len(res))
	assert.Equal(t, expected, res)
}
