package parser

import (
	"github.com/ynori7/credential-detector/config"
	"regexp"
)

const (
	TypeGoComment    = "go_comment"
	TypeGoVariable   = "go_variable"
	TypeJsonVariable = "json_variable"
	TypeJsonListVal  = "json_list_value"
	TypeYamlVariable = "yaml_variable"
	TypeYamlListVal  = "yaml_list_value"
)

type Parser struct {
	config config.Config

	variableNameMatchers         []*regexp.Regexp
	variableNameExclusionMatcher *regexp.Regexp
	valueIncludeMatchers         []*regexp.Regexp
	valueExcludeMatchers         []*regexp.Regexp

	Results []Result
}

type Result struct {
	File  string
	Type  string
	Line  int
	Name  string
	Value string
}

func NewParser(conf config.Config) Parser {
	parser := Parser{
		config:                       conf,
		variableNameMatchers:         make([]*regexp.Regexp, len(conf.VariableNamePatterns)),
		variableNameExclusionMatcher: regexp.MustCompile(conf.VariableNameExclusionPattern),
		valueIncludeMatchers:         make([]*regexp.Regexp, len(conf.ValueMatchPatterns)),
		valueExcludeMatchers:         make([]*regexp.Regexp, len(conf.ValueExcludePatterns)),
		Results:                      make([]Result, 0),
	}

	for k, v := range conf.VariableNamePatterns {
		parser.variableNameMatchers[k] = regexp.MustCompile(v)
	}

	for k, v := range conf.ValueMatchPatterns {
		parser.valueIncludeMatchers[k] = regexp.MustCompile(v)
	}

	for k, v := range conf.ValueExcludePatterns {
		parser.valueExcludeMatchers[k] = regexp.MustCompile(v)
	}

	return parser
}

func (p *Parser) ParseFile(filepath string) {
	if p.isParsableGoFile(filepath) {
		p.parseGoFile(filepath)
	}

	if p.isParsableJsonFile(filepath) {
		p.ParseJsonFile(filepath)
	}

	if p.isParsableYamlFile(filepath) {
		p.ParseYamlFile(filepath)
	}
}

func (p *Parser) isPossiblyCredentialsVariable(varName string, value string) bool {
	// no point in considering empty values
	if value == "" {
		return false
	}

	// exclude any variables whose value is in our exclusion list (this would include things like defaults and test values)
	for _, m := range p.valueExcludeMatchers {
		if m.MatchString(value) {
			return false
		}
	}

	// include anything in our value inclusion list. This would include things like postgres uris regardless of the variable name
	for _, m := range p.valueIncludeMatchers {
		if m.MatchString(value) {
			return true
		}
	}

	// if exclusions are defined for variable names, check
	if p.config.VariableNameExclusionPattern != "" && p.variableNameExclusionMatcher.MatchString(varName) {
		return false
	}

	for _, m := range p.variableNameMatchers {
		// include variables which have potentially suspicious names, but only if the value does not also match (to exclude constants like const Token = "token")
		if m.MatchString(varName) && !m.MatchString(value) {
			return true
		}
	}

	return false
}

func (p *Parser) isPossiblyCredentialValue(v string) bool {
	for _, m := range p.valueIncludeMatchers {
		if m.MatchString(v) {
			return true
		}
	}

	return false
}
