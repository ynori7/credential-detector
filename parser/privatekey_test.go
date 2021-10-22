package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ynori7/credential-detector/config"
)

func Test_isParsablePrivateKeyFile(t *testing.T) {
	testcases := map[string]struct {
		path     string
		expected bool
	}{
		"No extension": {
			path:     "/etc/id_rsa",
			expected: true,
		},
		"Cert extension": {
			path:     "/home/blah/blah.cert",
			expected: true,
		},
		"Pem extension": {
			path:     "/home/blah/blah.pem",
			expected: true,
		},
		"Other extension": {
			path:     "/home/blah/blah.txt",
			expected: false,
		},
	}

	conf, err := config.ParseConfig(getTestConfig())
	require.NoError(t, err)
	parser := NewParser(conf)

	for testcase, testdata := range testcases {
		actual := parser.isParsablePrivateKeyFile(testdata.path)

		assert.Equal(t, testdata.expected, actual, testcase)
	}
}

func TestParser_PrivateKey(t *testing.T) {
	// given
	conf, err := config.ParseConfig(getTestConfig())
	require.NoError(t, err)
	file := "../testdata/dummy_id_rsa"
	expected := []Result{
		{
			File:  file,
			Type:  TypePrivateKey,
			Line:  1,
			Name:  "",
			Value: `-----BEGIN RSA PRIVATE KEY-----`,
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
