package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ynori7/credential-detector/config"
)

func TestBuildEditorData_NoOverride(t *testing.T) {
	defaults := &config.Config{
		MinPasswordLength:            8,
		ExcludeTests:                 true,
		ScanTypes:                    []string{config.ScanTypeGo, config.ScanTypeYaml},
		VariableNameExclusionPattern: "(?i)format",
		VariableNamePatterns:         []string{"(?i)secret"},
	}
	d := BuildEditorData(defaults, nil)

	assert.False(t, d.HasOverride)
	assert.Equal(t, 8, d.MinPasswordLength)
	assert.True(t, d.ExcludeTests)
	assert.Equal(t, []string{config.ScanTypeGo, config.ScanTypeYaml}, d.ScanTypes)
	assert.Equal(t, "(?i)format", d.VariableNameExclusionPattern)
	assert.Empty(t, d.ExtraVariableNamePatterns)
}

func TestBuildEditorData_WithOverride(t *testing.T) {
	defaults := &config.Config{
		MinPasswordLength:            6,
		ExcludeTests:                 true,
		ScanTypes:                    []string{config.ScanTypeGo},
		VariableNameExclusionPattern: "(?i)format",
		VariableNamePatterns:         []string{"(?i)secret"},
	}
	override := &config.Config{
		MinPasswordLength:            20,
		ExcludeTests:                 false,
		ScanTypes:                    []string{config.ScanTypeYaml},
		VariableNameExclusionPattern: "(?i)myexclusion",
		VariableNamePatterns:         []string{"(?i)extra"},
	}
	d := BuildEditorData(defaults, override)

	assert.True(t, d.HasOverride)
	// Replace fields take override values
	assert.Equal(t, 20, d.MinPasswordLength)
	assert.False(t, d.ExcludeTests)
	assert.Equal(t, []string{config.ScanTypeYaml}, d.ScanTypes)
	assert.Equal(t, "(?i)myexclusion", d.VariableNameExclusionPattern)
	// Append fields expose the override additions
	assert.Equal(t, []string{"(?i)extra"}, d.ExtraVariableNamePatterns)
}
