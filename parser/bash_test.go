package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ynori7/credential-detector/config"
)

func Test_isParsableBashFile(t *testing.T) {
	testcases := map[string]struct {
		path     string
		expected bool
	}{
		"No extension": {
			path:     "/etc/passwd",
			expected: false,
		},
		"Not bash extension": {
			path:     "/home/blah/test.blah",
			expected: false,
		},
		"Bash extension": {
			path:     "/home/blah/blah.sh",
			expected: true,
		},
		"Makefile": {
			path:     "/home/blah/Makefile",
			expected: true,
		},
		"makefile lowercase": {
			path:     "/home/blah/makefile",
			expected: true,
		},
	}

	conf, err := config.ParseConfig(getTestConfig())
	require.NoError(t, err)
	parser := NewParser(conf)

	for testcase, testdata := range testcases {
		actual := parser.isParsableBashFile(testdata.path)

		assert.Equal(t, testdata.expected, actual, testcase)
	}
}

func TestParser_Bash(t *testing.T) {
	// given
	conf, err := config.ParseConfig(getTestConfig())
	require.NoError(t, err)
	file := "../testdata/dummy.sh"
	expected := []Result{
		{
			File:           file,
			Type:           TypeBashVariable,
			Line:           13,
			Name:           "",
			Value:          `PASSWORD="123blahblah"`,
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

func TestParser_Makefile(t *testing.T) {
	// given
	conf, err := config.ParseConfig(getTestConfig())
	require.NoError(t, err)
	file := "../testdata/Makefile"
	expected := []Result{
		{
			File:           file,
			Type:           TypeBashVariable,
			Line:           5,
			Name:           "",
			Value:          `--googlePlacesApiKey=AIzaSyAxxxxxsgx7s_cSxxxxx9g9bxxxxxxUVgU`,
			CredentialType: "Google API Key",
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

func TestParser_Dockerfile(t *testing.T) {
	// given
	conf, err := config.ParseConfig(getTestConfig())
	require.NoError(t, err)
	file := "../testdata/Dockerfile"
	expected := []Result{
		{
			File:           file,
			Type:           TypeBashVariable,
			Line:           4,
			Name:           "",
			Value:          `ARG GOOGLE_API_KEY=AIzaSyAxxxxxsgx7s_cSxxxxx9g9bxxxxxxUVgU`,
			CredentialType: "",
		},
		{
			File:           file,
			Type:           TypeBashVariable,
			Line:           5,
			Name:           "",
			Value:          `ENV DB_PASSWORD="xK9mP2qLr7vTn4wZ"`,
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
