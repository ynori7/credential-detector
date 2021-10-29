package config

import (
	_ "embed" //justified because I said so
	"flag"
	"fmt"
	"io/ioutil"
	"strings"

	"gopkg.in/yaml.v2"
)

var (
	//ScanPath is the path which should be scanned
	ScanPath string
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
	// ScanTypePHP indicates PHP files
	ScanTypePHP = "php"
	// ScanTypeGeneric indicates a file parsable as generic text
	ScanTypeGeneric = "generic"
)

// Config contains all the configuration for the credential detector
type Config struct {
	VariableNamePatterns             []string `yaml:"variableNamePatterns,flow"`
	VariableNameExclusionPattern     string   `yaml:"variableNameExclusionPattern"`
	XMLAttributeNameExclusionPattern string   `yaml:"xmlAttributeNameExclusionPattern"`
	ValueMatchPatterns               []string `yaml:"valueMatchPatterns,flow"`
	ValueExcludePatterns             []string `yaml:"valueExcludePatterns,flow"`
	MinPasswordLength                int      `yaml:"minPasswordLength"`

	ExcludeTests    bool `yaml:"excludeTests"`
	ExcludeComments bool `yaml:"excludeComments"`

	TestDirectories []string `yaml:"testDirectories,flow"`
	IgnoreFiles     []string `yaml:"ignoreFiles,flow"`

	ScanTypes             []string `yaml:"scanTypes,flow"`
	GenericFileExtensions []string `yaml:"genericFileExtensions"`

	DisableOutputColors bool `yaml:"disableOutputColors"`
	Verbose             bool `yaml:"verbose"`
}

// New returns a new configuration
func New() (*Config, error) {
	var (
		configPath     string
		rootConfigPath string
	)

	flag.StringVar(&configPath, "config", "", "The path to the config yaml which defines additions/overrides to the base config")
	flag.StringVar(&rootConfigPath, "root_config", "", "The path to the config yaml which defines the base configuration")
	flag.StringVar(&ScanPath, "path", "", "The path to scan")
	flag.Parse()

	if ScanPath == "" {
		return nil, fmt.Errorf("the path flag must be provided")
	}

	return LoadConfig(configPath, rootConfigPath)
}

// LoadConfig loads configuration based on the provided config path and root config path. If rootConfigPath is empty, the default will be used
func LoadConfig(configPath, rootConfigPath string) (*Config, error) {
	var (
		rootConfig     *Config
		configAddition *Config
		err            error
	)
	if rootConfigPath != "" {
		rootConfig, err = loadFile(rootConfigPath)
		if err != nil {
			return nil, err
		}
	} else {
		rootConfig, err = ParseConfig(defaultConfig)
		if err != nil {
			return nil, err
		}
	}

	if configPath == "" {
		return rootConfig, nil
	}

	configAddition, err = loadFile(configPath)
	if err != nil {
		return nil, err
	}

	return mergeConfigs(rootConfig, configAddition), nil
}

// IsTestDirectory returns true if the given directory matches one of the configured test directories
func (c Config) IsTestDirectory(dir string) bool {
	for _, v := range c.TestDirectories {
		if strings.EqualFold(v, dir) {
			return true
		}
	}
	return false
}

// IsIgnoreFile returns true if the given file/directory matches one of the configured files to ignore
func (c Config) IsIgnoreFile(dir string) bool {
	for _, v := range c.IgnoreFiles {
		if strings.EqualFold(v, dir) {
			return true
		}
	}
	return false
}

//go:embed default_config.yaml
var defaultConfig []byte

// ParseConfig parses the given YAML file data into a configuration object
func ParseConfig(data []byte) (*Config, error) {
	c := &Config{}
	if err := yaml.Unmarshal(data, &c); err != nil {
		return c, err
	}

	return c, nil
}

func loadFile(path string) (*Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	conf, err := ParseConfig(data)
	if err != nil {
		return nil, fmt.Errorf("error loading configuration from %s: %s", path, err.Error())
	}

	return conf, nil
}

func mergeConfigs(root *Config, additions *Config) *Config {
	if additions.MinPasswordLength > 0 {
		root.MinPasswordLength = additions.MinPasswordLength
	}

	if len(additions.ScanTypes) > 0 {
		root.ScanTypes = additions.ScanTypes
	}

	root.ExcludeTests = additions.ExcludeTests
	root.ExcludeComments = additions.ExcludeComments
	root.Verbose = additions.Verbose
	root.DisableOutputColors = additions.DisableOutputColors

	root.TestDirectories = append(root.TestDirectories, additions.TestDirectories...)
	root.IgnoreFiles = append(root.IgnoreFiles, additions.IgnoreFiles...)
	root.VariableNamePatterns = append(root.VariableNamePatterns, additions.VariableNamePatterns...)
	root.ValueExcludePatterns = append(root.ValueExcludePatterns, additions.ValueExcludePatterns...)
	root.ValueMatchPatterns = append(root.ValueMatchPatterns, additions.ValueMatchPatterns...)
	root.GenericFileExtensions = append(root.GenericFileExtensions, additions.GenericFileExtensions...)

	if additions.VariableNameExclusionPattern != "" {
		root.VariableNameExclusionPattern = additions.VariableNameExclusionPattern
	}

	if additions.XMLAttributeNameExclusionPattern != "" {
		root.XMLAttributeNameExclusionPattern = additions.XMLAttributeNameExclusionPattern
	}

	return root
}
