package parser

import (
	fp "path/filepath"
	"regexp"
	"strings"

	"github.com/ynori7/credential-detector/config"
)

// Types indicate the credential finding type
const (
	TypeGoComment = iota
	TypeGoVariable
	TypeJSONVariable
	TypeJSONListVal
	TypeYamlVariable
	TypeYamlListVal
	TypePropertiesComment
	TypePropertiesValue
	TypePrivateKey
)

// Parser searches the given files and maintains a list of hard-coded credentials stored in Results
type Parser struct {
	config config.Config

	scanTypes map[string]struct{}

	variableNameMatchers         []*regexp.Regexp
	variableNameExclusionMatcher *regexp.Regexp
	valueIncludeMatchers         []*regexp.Regexp
	valueExcludeMatchers         []*regexp.Regexp

	// Results is the list of findings
	Results []Result
}

// Result is a hard-coded credential finding
type Result struct {
	File  string
	Type  int
	Line  int
	Name  string
	Value string
}

// NewParser returns a new parser with the given configuration
func NewParser(conf config.Config) Parser {
	parser := Parser{
		config:                       conf,
		scanTypes:                    make(map[string]struct{}),
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

	for _, v := range conf.ScanTypes {
		parser.scanTypes[v] = struct{}{}
	}

	return parser
}

// ParseFile parses the given file (if possible) and collects potential credentials
func (p *Parser) ParseFile(filepath string) {
	switch {
	case p.isParsableGoFile(filepath):
		p.parseGoFile(filepath)
	case p.isParsableJSONFile(filepath):
		p.parseJSONFile(filepath)
	case p.isParsableYamlFile(filepath):
		p.parseYamlFile(filepath)
	case p.isParsablePropertiesFile(filepath):
		p.parsePropertiesFile(filepath)
		fallthrough //we also handle hidden files with no extension here, so we should also check the next case
	case p.isParsablePrivateKeyFile(filepath):
		p.parsePrivateKeyFile(filepath)
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
	// exclude any variables whose value is in our exclusion list (this would include things like defaults and test values)
	for _, m := range p.valueExcludeMatchers {
		if m.MatchString(v) {
			return false
		}
	}

	// include anything in our value inclusion list. This would include things like postgres uris regardless of the variable name
	for _, m := range p.valueIncludeMatchers {
		if m.MatchString(v) {
			return true
		}
	}

	return false
}

func getFileNameAndExtension(filepath string) (string, string) {
	extension := fp.Ext(filepath)
	dir := fp.Dir(filepath)

	name := strings.TrimPrefix(filepath, dir)
	name = strings.TrimPrefix(name, "/")
	name = strings.TrimSuffix(name, extension)

	return name, extension
}
