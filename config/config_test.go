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
		ValueMatchPatterns:           []ValueMatchPattern{{Name: "test", Pattern: "postgres"}},
		VariableValueExcludePatterns: []string{"dummy", "test"},
		FullTextValueExcludePatterns: []string{"asdf"},
		MinPasswordLength:            6,
		ExcludeTests:                 false,
		ExcludeComments:              false,
		TestDirectories:              []string{"test", "testdata", "example", "data"},
		ScanTypes:                    []string{"go", "yaml", "json"},
		DisableOutputColors:          false,
		Verbose:                      false,
	}

	actual, err := LoadConfig("testdata/config.yaml", "testdata/root-config.yaml")
	require.NoError(t, err)

	assert.Equal(t, expected, actual)
}

func TestMergeConfigs_NoAdditionalConfig(t *testing.T) {
	expected := &Config{
		VariableNamePatterns:         []string{"test", "blah"},
		VariableNameExclusionPattern: "asdf|jkl",
		ValueMatchPatterns:           []ValueMatchPattern{{Name: "test", Pattern: "postgres"}},
		VariableValueExcludePatterns: []string{"dummy", "test"},
		FullTextValueExcludePatterns: []string{"asdf"},
		MinPasswordLength:            6,
		ExcludeTests:                 true,
		ExcludeComments:              false,
		TestDirectories:              []string{"test", "testdata", "example", "data"},
		ScanTypes:                    []string{"go", "yaml", "json", "properties", "privatekey", "xml"},
		DisableOutputColors:          false,
		Verbose:                      false,
	}

	actual, err := LoadConfig("", "testdata/root-config.yaml")
	require.NoError(t, err)

	assert.Equal(t, expected, actual)
}

func TestMergeConfigs_NoRootProvided(t *testing.T) {
	expected, err := ParseConfig(defaultConfig)
	require.NoError(t, err)

	actual, err := LoadConfig("", "")
	require.NoError(t, err)

	assert.Equal(t, expected, actual)
}

func TestMergeConfigs_Error(t *testing.T) {
	_, err := LoadConfig("asdfsadf", "")
	assert.Error(t, err)

	_, err = LoadConfig("", "asdfasdf")
	assert.Error(t, err)

	_, err = LoadConfig("", "config.go")
	assert.Error(t, err)
}

func TestMergeConfigs_IsTestDirectory(t *testing.T) {
	conf := &Config{
		VariableNamePatterns:         []string{"test", "blah"},
		VariableNameExclusionPattern: "asdf|jkl",
		ValueMatchPatterns:           []ValueMatchPattern{{Name: "test", Pattern: "postgres"}},
		VariableValueExcludePatterns: []string{"dummy", "test"},
		FullTextValueExcludePatterns: []string{"asdf"},
		MinPasswordLength:            6,
		ExcludeTests:                 true,
		ExcludeComments:              false,
		TestDirectories:              []string{"test", "testdata", "example", "data"},
		ScanTypes:                    []string{"go", "yaml", "json", "properties", "privatekey", "xml"},
		DisableOutputColors:          false,
		Verbose:                      false,
	}

	expected := map[string]bool{
		"test":   true,
		"latest": false,
		"blah":   false,
		"Test":   true,
	}

	for dir, expectedVal := range expected {
		assert.Equal(t, expectedVal, conf.IsTestDirectory(dir), dir)
	}
}
