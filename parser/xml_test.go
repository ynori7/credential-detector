package parser

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ynori7/credential-detector/config"
	"sort"
	"testing"
)

func Test_isParsableXMLFile(t *testing.T) {
	testcases := map[string]struct {
		path     string
		expected bool
	}{
		"No extension": {
			path:     "/etc/passwd",
			expected: false,
		},
		"No extension, name is xml": {
			path:     "/etc/xml",
			expected: false,
		},
		"Not xml extension": {
			path:     "/home/blah/test.txt",
			expected: false,
		},
		"Not xml extension, hidden file": {
			path:     "/home/blah/.test.swp",
			expected: false,
		},
		"Xml extension, hidden file": {
			path:     "/home/blah/.blah.xml",
			expected: true,
		},
		"Xml extension": {
			path:     "/home/blah/blah.xml",
			expected: true,
		},
	}

	conf, err := config.ParseConfig(getTestConfig())
	require.NoError(t, err)
	parser := NewParser(conf)

	for testcase, testdata := range testcases {
		actual := parser.isParsableXMLFile(testdata.path)

		assert.Equal(t, testdata.expected, actual, testcase)
	}
}

func TestParser_XML(t *testing.T) {
	// given
	conf, err := config.ParseConfig(getTestConfig())
	require.NoError(t, err)
	file := "../testdata/dummy.xml"
	expected := []Result{
		{
			File:  file,
			Type:  TypeXMLElement,
			Line:  0,
			Name:  "token",
			Value: `akljwerlkjweker`,
		},
		{
			File:  file,
			Type:  TypeXMLElement,
			Line:  0,
			Name:  "authToken",
			Value: `akljwerlkjweker`,
		},
		{
			File:  file,
			Type:  TypeXMLAttribute,
			Line:  0,
			Name:  "property",
			Value: `<property name="api_key" value="ajskdjlwlkej3k#kd3">`,
		},
	}

	// when
	parser := NewParser(conf)
	parser.ParseFile(file)

	// then
	res := parser.Results
	sort.Slice(res, func(i, j int) bool {
		return res[i].Name < res[j].Name
	})
	sort.Slice(expected, func(i, j int) bool {
		return expected[i].Name < expected[j].Name
	})

	assert.Equal(t, len(expected), len(res))
	assert.Equal(t, expected, res)
}
