package config

import (
	_ "embed"
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

const (
	ScanType_Go   = "go"
	ScanType_Yaml = "yaml"
	ScanType_Json = "json"
)

type Config struct {
	VariableNamePatterns         []string `yaml:"variableNamePatterns,flow"`
	VariableNameExclusionPattern string   `yaml:"variableNameExclusionPattern"`
	ValueMatchPatterns           []string `yaml:"valueMatchPatterns,flow"`
	ValueExcludePatterns         []string `yaml:"valueExcludePatterns,flow"`

	ExcludeTests    bool `yaml:"excludeTests"`
	ExcludeComments bool `yaml:"excludeComments"`

	TestDirectories []string `yaml:"testDirectories,flow"`
	ScanTypes       []string `yaml:"scanTypes,flow"`

	DisableOutputColors bool `yaml:"disableOutputColors"`
	Verbose             bool `yaml:"verbose"`
}

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
