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
