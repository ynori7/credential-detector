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

	// when
	parser := NewParser(conf)
	parseFileForTest(parser, file)

	// then
	res := parser.Results
	assert.Equal(t, 5, len(res))

	// Separate JS-parsed results from JSON-walked results
	jsResults := make([]Result, 0)
	jsonResults := make([]Result, 0)
	for _, r := range res {
		if r.Type == TypeJSONVariable || r.Type == TypeJSONListVal {
			jsonResults = append(jsonResults, r)
		} else {
			jsResults = append(jsResults, r)
		}
	}

	// 3 results from JS line-by-line parsing
	assert.Equal(t, 3, len(jsResults))

	jsByName := make(map[string]Result)
	for _, r := range jsResults {
		if r.Name != "" {
			jsByName[r.Name] = r
		}
	}
	assert.Equal(t, TypeJSVariable, jsByName["password"].Type)
	assert.Equal(t, `"supersecure123!@#$"`, jsByName["password"].Value)
	assert.Equal(t, 11, jsByName["password"].Line)

	assert.Equal(t, TypeJSVariable, jsByName["apiKey"].Type)
	assert.Equal(t, `"sk-html-1234567890abcd"`, jsByName["apiKey"].Value)

	assert.Equal(t, TypeJSVariable, jsByName["dbConnection"].Type)

	// 2 results from JSON array parsing (USERS array with password fields)
	assert.Equal(t, 2, len(jsonResults))
	for _, r := range jsonResults {
		assert.Equal(t, TypeJSONVariable, r.Type)
		assert.Equal(t, "password", r.Name)
	}
}
