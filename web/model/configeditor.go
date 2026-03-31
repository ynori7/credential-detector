package model

import (
	"github.com/ynori7/credential-detector/config"
)

// ConfigEditorData is the template data for the config editor partial.
type ConfigEditorData struct {
	// Replace fields — effective value (override wins, then defaults)
	VariableNameExclusionPattern     string
	XMLAttributeNameExclusionPattern string
	MinPasswordLength                int
	ExcludeTests                     bool
	ExcludeComments                  bool
	Verbose                          bool
	ScanTypes                        []string

	// Append fields — only the user's overrides (empty if none saved)
	ExtraVariableNamePatterns         []string
	ExtraValueMatchPatterns           []config.ValueMatchPattern
	ExtraVariableValueExcludePatterns []string
	ExtraFullTextValueExcludePatterns []string
	ExtraTestDirectories              []string
	ExtraIgnoreFiles                  []string
	ExtraGenericFileExtensions        []string
	ExtraGenericCodeFileExtensions    []string

	// Reference: the base defaults shown collapsed for context
	Defaults     *config.Config
	AllScanTypes []string

	// Whether a custom config is currently active
	HasOverride bool
}

// BuildEditorData constructs the ConfigEditorData for the template, applying any override values on top of the defaults.
func BuildEditorData(defaults, override *config.Config) ConfigEditorData {
	d := ConfigEditorData{
		Defaults:     defaults,
		AllScanTypes: AllScanTypes,
		// Seed replace fields with effective defaults
		VariableNameExclusionPattern:     defaults.VariableNameExclusionPattern,
		XMLAttributeNameExclusionPattern: defaults.XMLAttributeNameExclusionPattern,
		MinPasswordLength:                defaults.MinPasswordLength,
		ExcludeTests:                     defaults.ExcludeTests,
		ExcludeComments:                  defaults.ExcludeComments,
		Verbose:                          defaults.Verbose,
		ScanTypes:                        defaults.ScanTypes,
	}

	if override == nil {
		return d
	}

	d.HasOverride = true

	// Apply override to replace fields
	if override.VariableNameExclusionPattern != "" {
		d.VariableNameExclusionPattern = override.VariableNameExclusionPattern
	}
	if override.XMLAttributeNameExclusionPattern != "" {
		d.XMLAttributeNameExclusionPattern = override.XMLAttributeNameExclusionPattern
	}
	if override.MinPasswordLength > 0 {
		d.MinPasswordLength = override.MinPasswordLength
	}
	d.ExcludeTests = override.ExcludeTests
	d.ExcludeComments = override.ExcludeComments
	d.Verbose = override.Verbose
	if len(override.ScanTypes) > 0 {
		d.ScanTypes = override.ScanTypes
	}

	// Populate append fields with the override's additions
	d.ExtraVariableNamePatterns = override.VariableNamePatterns
	d.ExtraValueMatchPatterns = override.ValueMatchPatterns
	d.ExtraVariableValueExcludePatterns = override.VariableValueExcludePatterns
	d.ExtraFullTextValueExcludePatterns = override.FullTextValueExcludePatterns
	d.ExtraTestDirectories = override.TestDirectories
	d.ExtraIgnoreFiles = override.IgnoreFiles
	d.ExtraGenericFileExtensions = override.GenericFileExtensions
	d.ExtraGenericCodeFileExtensions = override.GenericCodeFileExtensions

	return d
}
