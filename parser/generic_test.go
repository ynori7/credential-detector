package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ynori7/credential-detector/config"
)

func Test_isParsableGenericFile(t *testing.T) {
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
			expected: true,
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
		actual := parser.isParsableGenericFile(testdata.path)

		assert.Equal(t, testdata.expected, actual, testcase)
	}
}

func TestParser_Generic(t *testing.T) {
	// given
	conf, err := config.ParseConfig(getTestConfig())
	require.NoError(t, err)
	file := "../testdata/dummy.md"
	expected := []Result{
		{
			File:  file,
			Type:  TypeGeneric,
			Line:  6,
			Name:  "",
			Value: `final SendGrid sendGrid = new SendGrid("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");`,
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
