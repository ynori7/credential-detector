package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMergeConfigs(t *testing.T) {
	expected := &Config{
		VariableNamePatterns:         []string{"test", "blah", "whatever"},
		VariableNameExclusionPattern: "werwer",
		ValueMatchPatterns:           []string{"postgres"},
		ValueExcludePatterns:         []string{"dummy", "test"},
		MinPasswordLength:            6,
		ExcludeTests:                 false,
		ExcludeComments:              false,
		TestDirectories:              []string{"test", "testdata", "example", "data"},
		ScanTypes:                    []string{"go", "yaml", "json"},
		DisableOutputColors:          false,
		Verbose:                      false,
	}

	actual, err := loadConfig("testdata/config.yaml", "testdata/root-config.yaml")
	require.NoError(t, err)

	assert.Equal(t, expected, actual)
}

func TestMergeConfigs_NoAdditionalConfig(t *testing.T) {
	expected := &Config{
		VariableNamePatterns:         []string{"test", "blah"},
		VariableNameExclusionPattern: "asdf|jkl",
		ValueMatchPatterns:           []string{"postgres"},
		ValueExcludePatterns:         []string{"dummy", "test"},
		MinPasswordLength:            6,
		ExcludeTests:                 true,
		ExcludeComments:              false,
		TestDirectories:              []string{"test", "testdata", "example", "data"},
		ScanTypes:                    []string{"go", "yaml", "json", "properties", "privatekey", "xml"},
		DisableOutputColors:          false,
		Verbose:                      false,
	}

	actual, err := loadConfig("", "testdata/root-config.yaml")
	require.NoError(t, err)

	assert.Equal(t, expected, actual)
}

func TestMergeConfigs_NoRootProvided(t *testing.T) {
	expected, err := ParseConfig(defaultConfig)
	require.NoError(t, err)

	actual, err := loadConfig("", "")
	require.NoError(t, err)

	assert.Equal(t, expected, actual)
}

func TestMergeConfigs_Error(t *testing.T) {
	_, err := loadConfig("asdfsadf", "")
	assert.Error(t, err)

	_, err = loadConfig("", "asdfasdf")
	assert.Error(t, err)
}