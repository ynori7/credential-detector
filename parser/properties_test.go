package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ynori7/credential-detector/config"
)

func Test_isParsablePropertiesFile(t *testing.T) {
	testcases := map[string]struct {
		path     string
		expected bool
	}{
		"No extension": {
			path:     "/etc/passwd",
			expected: false,
		},
		"No extension, name is properties": {
			path:     "/etc/properties",
			expected: false,
		},
		"Not properties extension": {
			path:     "/home/blah/test.txt",
			expected: false,
		},
		"Not properties extension, hidden file": {
			path:     "/home/blah/.test.swp",
			expected: false,
		},
		"Properties extension, hidden file": {
			path:     "/home/blah/.blah.properties",
			expected: true,
		},
		"No extension, hidden file": {
			path:     "/home/blah/.env",
			expected: true,
		},
		"Properties extension": {
			path:     "/home/blah/blah.properties",
			expected: true,
		},
	}

	conf, err := config.ParseConfig(getTestConfig())
	require.NoError(t, err)
	parser := NewParser(conf)

	for testcase, testdata := range testcases {
		actual := parser.isParsablePropertiesFile(testdata.path)

		assert.Equal(t, testdata.expected, actual, testcase)
	}
}

func TestParser_Properties(t *testing.T) {
	// given
	conf, err := config.ParseConfig(getTestConfig())
	require.NoError(t, err)
	file := "../testdata/dummy.properties"
	expected := []Result{
		{
			File:  file,
			Type:  TypePropertiesValue,
			Line:  3,
			Name:  "APP_SECRET",
			Value: `2342342kjasdre`,
		},
		{
			File:           file,
			Type:           TypePropertiesComment,
			Line:           5,
			Name:           "",
			Value:          `#POSTGRES_URI=postgres://myuser:password123@somepostgresdb:5432/mydb?sslmode=disable`,
			CredentialType: "Postgres URI",
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
