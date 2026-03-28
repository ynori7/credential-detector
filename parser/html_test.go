package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ynori7/credential-detector/config"
)

func Test_isParsableHTMLFile(t *testing.T) {
	testcases := map[string]struct {
		path     string
		expected bool
	}{
		"No extension": {
			path:     "/etc/passwd",
			expected: false,
		},
		"Not HTML extension": {
			path:     "/home/blah/test.xml",
			expected: false,
		},
		"HTML extension": {
			path:     "/home/blah/index.html",
			expected: true,
		},
		"XHTML extension": {
			path:     "/home/blah/page.xhtml",
			expected: true,
		},
	}

	conf, err := config.ParseConfig(getTestConfig())
	require.NoError(t, err)
	parser := NewParser(conf)

	for testcase, testdata := range testcases {
		actual := parser.isParsableHTMLFile(testdata.path)

		assert.Equal(t, testdata.expected, actual, testcase)
	}
}

func TestParser_HTML(t *testing.T) {
	// given
	conf, err := config.ParseConfig(getTestConfig())
	require.NoError(t, err)
	file := "../testdata/dummy.html"

	expected := []Result{
		{
			File:  file,
			Type:  TypeJSVariable,
			Line:  11,
			Name:  "password",
			Value: `"supersecure123!@#$"`,
		},
		{
			File:  file,
			Type:  TypeJSVariable,
			Line:  12,
			Name:  "apiKey",
			Value: `"sk-html-1234567890abcd"`,
		},
		{
			File:  file,
			Type:  TypeJSVariable,
			Line:  19,
			Name:  "dbConnection",
			Value: `"postgres://webuser:webpass123@db.example.com:5432/webapp?sslmode=disable"`,
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
