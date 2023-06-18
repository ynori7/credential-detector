package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ynori7/credential-detector/config"
)

func Test_isParsableGenericCodeFile(t *testing.T) {
	testcases := map[string]struct {
		path     string
		expected bool
	}{
		"No extension": {
			path:     "/etc/passwd",
			expected: false,
		},
		"No extension, name is generic": {
			path:     "/etc/generic",
			expected: false,
		},
		"Not generic extension": {
			path:     "/home/blah/test.blah",
			expected: false,
		},
		"Not generic extension, hidden file": {
			path:     "/home/blah/.test.swp",
			expected: false,
		},
		"Generic extension, hidden file": {
			path:     "/home/blah/.blah.txt",
			expected: false,
		},
		"No extension, hidden file": {
			path:     "/home/blah/.env",
			expected: false,
		},
		"Generic extension": {
			path:     "/home/blah/blah.java",
			expected: true,
		},
	}

	conf, err := config.ParseConfig(getTestConfig())
	require.NoError(t, err)
	parser := NewParser(conf)

	for testcase, testdata := range testcases {
		actual := parser.isParsableGenericCodeFile(testdata.path)

		assert.Equal(t, testdata.expected, actual, testcase)
	}
}

func TestParser_GenericCode(t *testing.T) {
	// given
	conf, err := config.ParseConfig(getTestConfig())
	require.NoError(t, err)
	file := "../testdata/dummy.java"
	expected := []Result{
		{
			File:           file,
			Type:           TypeGeneric,
			Line:           10,
			Name:           "",
			Value:          `private String someTokenPassword = "AERWEk33se";`,
			CredentialType: "",
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
