package config

import (
	_ "embed"
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

type Config struct {
	VariableNamePatterns         []string `yaml:"variableNamePatterns,flow"`
	VariableNameExclusionPattern string   `yaml:"variableNameExclusionPattern"`
	ValueMatchPatterns           []string `yaml:"valueMatchPatterns,flow"`
	ValueExcludePatterns         []string `yaml:"valueExcludePatterns,flow"`

	ExcludeTests     bool `yaml:"excludeTests"`
	ExcludeComments  bool `yaml:"excludeComments"`
	IncludeJsonFiles bool `yaml:"includeJsonFiles"`
	IncludeYamlFiles bool `yaml:"includeYamlFiles"`

	DisableOutputColors bool `yaml:"disableOutputColors"`
	Verbose             bool `yaml:"verbose"`
}

//go:embed default_config.yaml
var defaultConfig []byte

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

func ParseConfig(data []byte) (Config, error) {
	c := Config{}
	if err := yaml.Unmarshal(data, &c); err != nil {
		return c, err
	}

	return c, nil
}
