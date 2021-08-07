package main

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

type Config struct {
	VariableNamePatterns         []string `yaml:"variableNamePatterns,flow"`
	VariableNameExclusionPattern string   `yaml:"variableNameExclusionPattern"`
	ValueMatchPatterns           []string `yaml:"valueMatchPatterns,flow"`
	ValueExcludePatterns         []string `yaml:"valueExcludePatterns,flow"`
	ExcludeTests                 bool     `yaml:"excludeTests"`
	ExcludeComments              bool     `yaml:"excludeComments"`
	DisableOutputColors          bool     `yaml:"disableOutputColors"`
}

var (
	defaultVariableNamePatterns = []string{
		"(?i)passwd|password",
		"(?i)secret",
		"(?i)token",
		"(?i)apiKey|api[_-]key",
		"(?i)accessKey|access[_-]key",
		"(?i)bearer",
		"(?i)credentials",
		"salt|SALT|Salt",
	}
)

func LoadConfig(path string) (Config, error) {
	if path == "" {
		return Config{
			VariableNamePatterns: defaultVariableNamePatterns,
		}, nil
	}

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	return parseConfig(data)
}

func parseConfig(data []byte) (Config, error) {
	c := Config{}
	if err := yaml.Unmarshal(data, &c); err != nil {
		return c, err
	}

	return c, nil
}
