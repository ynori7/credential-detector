package config

import (
	_ "embed" //justified because I said so
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

const (
	// ScanTypeGo indicates Golang files
	ScanTypeGo = "go"
	// ScanTypeYaml indicates YAML files
	ScanTypeYaml = "yaml"
	// ScanTypeJSON indicates JSON files
	ScanTypeJSON = "json"
	// ScanTypeProperties indicates properties files
	ScanTypeProperties = "properties"
	// ScanTypePrivateKey indicates private key files
	ScanTypePrivateKey = "privatekey"
	// ScanTypeXML indicates XML files
	ScanTypeXML = "xml"
)

// Config contains all the configuration for the credential detector
type Config struct {
	VariableNamePatterns         []string `yaml:"variableNamePatterns,flow"`
	VariableNameExclusionPattern string   `yaml:"variableNameExclusionPattern"`
	ValueMatchPatterns           []string `yaml:"valueMatchPatterns,flow"`
	ValueExcludePatterns         []string `yaml:"valueExcludePatterns,flow"`
	MinPasswordLength            int      `yaml:"minPasswordLength"`

	ExcludeTests    bool `yaml:"excludeTests"`
	ExcludeComments bool `yaml:"excludeComments"`

	TestDirectories []string `yaml:"testDirectories,flow"`
	ScanTypes       []string `yaml:"scanTypes,flow"`

	DisableOutputColors bool `yaml:"disableOutputColors"`
	Verbose             bool `yaml:"verbose"`
}

// IsTestDirectory returns true if the given directory matches one of the configured test directories
func (c Config) IsTestDirectory(dir string) bool {
	for _, v := range c.TestDirectories {
		if v == dir {
			return true
		}
	}
	return false
}

//go:embed default_config.yaml
var defaultConfig []byte

// LoadConfig loads configuration from the given file path
func LoadConfig(path string) (Config, error) {
	if path == "" {
		return ParseConfig(defaultConfig)
	}

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	return ParseConfig(data)
}

// ParseConfig parses the given YAML file data into a configuration object
func ParseConfig(data []byte) (Config, error) {
	c := Config{}
	if err := yaml.Unmarshal(data, &c); err != nil {
		return c, err
	}

	return c, nil
}
