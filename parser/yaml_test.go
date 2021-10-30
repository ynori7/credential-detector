package parser

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ynori7/credential-detector/config"
)

func Test_isParsableYamlFile(t *testing.T) {
	testcases := map[string]struct {
		path     string
		expected bool
	}{
		"No extension": {
			path:     "/etc/passwd",
			expected: false,
		},
		"No extension, name is yaml": {
			path:     "/etc/yaml",
			expected: false,
		},
		"No extension, name is yml": {
			path:     "/etc/yml",
			expected: false,
		},
		"Not yaml extension": {
			path:     "/home/blah/test.txt",
			expected: false,
		},
		"Not yaml extension, hidden file": {
			path:     "/home/blah/.test.swp",
			expected: false,
		},
		"Yaml extension, hidden file": {
			path:     "/home/blah/.blah.yaml",
			expected: true,
		},
		"Yaml extension": {
			path:     "/home/blah/blah.yaml",
			expected: true,
		},
		"Yml extension": {
			path:     "/home/blah/blah.yml",
			expected: true,
		},
	}

	conf, err := config.ParseConfig(getTestConfig())
	require.NoError(t, err)
	parser := NewParser(conf)

	for testcase, testdata := range testcases {
		actual := parser.isParsableYamlFile(testdata.path)

		assert.Equal(t, testdata.expected, actual, testcase)
	}
}

func TestParser_Yaml(t *testing.T) {
	// given
	conf, err := config.ParseConfig(getTestConfig())
	require.NoError(t, err)
	file := "../testdata/dummy.yaml"
	expected := []Result{
		{
			File:  file,
			Type:  TypeYamlVariable,
			Line:  0,
			Name:  "accessKey",
			Value: `2342342kjasdre`,
		},
		{
			File:           file,
			Type:           TypeYamlListVal,
			Line:           0,
			Name:           "args",
			Value:          `postgres://myuser:password123@somepostgresdb:5432/mydb?sslmode=disable`,
			CredentialType: "Postgres URI",
		},
	}

	// when
	parser := NewParser(conf)
	parseFileForTest(parser, file)

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
