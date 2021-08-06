package main

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

type Config struct {
	VariableNamePattern          string   `yaml:"variableNamePattern"`
	VariableNameExclusionPattern string   `yaml:"variableNameExclusionPattern"`
	ValueMatchPatterns           []string `yaml:"valueMatchPatterns,flow"`
	ValueExcludePatterns         []string `yaml:"valueExcludePatterns,flow"`
	ExcludeTests                 bool     `yaml:"excludeTests"`
}

var (
	defaultVariableNamePattern = `(?i)passwd|password|pwd|secret|token|pw|apiKey|api_key|accessKey|bearer|credentials`
)

func LoadConfig(path string) (Config, error) {
	if path == "" {
		return Config{
			VariableNamePattern: defaultVariableNamePattern,
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
