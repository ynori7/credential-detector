package parser

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ynori7/credential-detector/config"
)

func Test_isParsableJsonFile(t *testing.T) {
	testcases := map[string]struct {
		path     string
		expected bool
	}{
		"No extension": {
			path:     "/etc/passwd",
			expected: false,
		},
		"No extension, name is json": {
			path:     "/etc/json",
			expected: false,
		},
		"Not json extension": {
			path:     "/home/blah/test.txt",
			expected: false,
		},
		"Not json extension, hidden file": {
			path:     "/home/blah/.test.swp",
			expected: false,
		},
		"Json extension, hidden file": {
			path:     "/home/blah/.blah.json",
			expected: true,
		},
		"Json extension": {
			path:     "/home/blah/blah.json",
			expected: true,
		},
	}

	conf, err := config.ParseConfig(getTestConfig())
	require.NoError(t, err)
	parser := NewParser(conf)

	for testcase, testdata := range testcases {
		actual := parser.isParsableJsonFile(testdata.path)

		assert.Equal(t, testdata.expected, actual, testcase)
	}
}

func TestParser_Json(t *testing.T) {
	// given
	conf, err := config.ParseConfig(getTestConfig())
	require.NoError(t, err)
	file := "../testdata/dummy.json"
	expected := []Result{
		{
			File:  file,
			Type:  TypeJsonVariable,
			Line:  0,
			Name:  "apiKey",
			Value: `aslkdjflkjwe#Kjkjoi3`,
		},
		{
			File:  file,
			Type:  TypeJsonVariable,
			Line:  0,
			Name:  "secret",
			Value: `23423Ksk3s`,
		},
		{
			File:  file,
			Type:  TypeJsonVariable,
			Line:  0,
			Name:  "token",
			Value: `lkaskjlklejer#4`,
		},
		{
			File:  file,
			Type:  TypeJsonListVal,
			Line:  0,
			Name:  "stuff2",
			Value: `postgres://myuser:password123@somepostgresdb:5432/mydb?sslmode=disable`,
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

func TestParser_JsonList(t *testing.T) {
	// given
	conf, err := config.ParseConfig(getTestConfig())
	require.NoError(t, err)
	file := "../testdata/dummylist.json"
	expected := []Result{
		{
			File:  file,
			Type:  TypeJsonVariable,
			Line:  0,
			Name:  "Password",
			Value: `asdfawekrjwe`,
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
