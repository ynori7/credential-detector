package parser

import (
	"github.com/ynori7/credential-detector/config"
	"os"
	fp "path/filepath"
	"regexp"
	"strings"
	"sync"
)

// Types indicate the credential finding type
const (
	TypeGoComment = iota
	TypeGoVariable
	TypeGoOther

	TypeJSONVariable
	TypeJSONListVal

	TypeYamlVariable
	TypeYamlListVal

	TypePropertiesComment
	TypePropertiesValue

	TypePrivateKey

	TypeXMLElement
	TypeXMLAttribute

	TypePHPVariable
	TypePHPHeredoc
	TypePHPConstant
	TypePHPComment
	TypePHPOther

	TypeGeneric
)

// Parser searches the given files and maintains a list of hard-coded credentials stored in Results
type Parser struct {
	config *config.Config

	scanTypes map[string]struct{}

	variableNameMatchers             []*regexp.Regexp
	variableNameExclusionMatcher     *regexp.Regexp
	xmlAttributeNameExclusionMatcher *regexp.Regexp
	valueIncludeMatchers             map[string]*regexp.Regexp
	valueExcludeMatchers             []*regexp.Regexp

	// Results is the list of findings
	Results         []Result
	resultChan      chan Result
	resultBuildDone chan struct{}
}

// Result is a hard-coded credential finding
type Result struct {
	File           string
	Type           int
	Line           int
	Name           string
	Value          string
	CredentialType string //only filled for cases where it's not clear from the context
}

// NewParser returns a new parser with the given configuration
func NewParser(conf *config.Config) *Parser {
	parser := &Parser{
		config:                           conf,
		scanTypes:                        make(map[string]struct{}),
		variableNameMatchers:             make([]*regexp.Regexp, len(conf.VariableNamePatterns)),
		variableNameExclusionMatcher:     regexp.MustCompile(conf.VariableNameExclusionPattern),
		xmlAttributeNameExclusionMatcher: regexp.MustCompile(conf.XMLAttributeNameExclusionPattern),
		valueIncludeMatchers:             make(map[string]*regexp.Regexp, len(conf.ValueMatchPatterns)),
		valueExcludeMatchers:             make([]*regexp.Regexp, len(conf.ValueExcludePatterns)),
		Results:                          make([]Result, 0),
		resultChan:                       make(chan Result, 8),
		resultBuildDone:                  make(chan struct{}),
	}

	for k, v := range conf.VariableNamePatterns {
		parser.variableNameMatchers[k] = regexp.MustCompile(v)
	}

	for _, v := range conf.ValueMatchPatterns {
		parser.valueIncludeMatchers[v.Name] = regexp.MustCompile(v.Pattern)
	}

	for k, v := range conf.ValueExcludePatterns {
		parser.valueExcludeMatchers[k] = regexp.MustCompile(v)
	}

	for _, v := range conf.ScanTypes {
		parser.scanTypes[v] = struct{}{}
	}

	go parser.buildResults()

	return parser
}

func (p *Parser) buildResults() {
	for res := range p.resultChan {
		p.Results = append(p.Results, res)
	}
	close(p.resultBuildDone)
}

// Scan initiates the recursive scan of all files/directories in the given path
func (p *Parser) Scan(scanPath string) error {
	wg := sync.WaitGroup{}

	err := fp.Walk(scanPath,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if p.config.IsIgnoreFile(info.Name()) {
				//skip ignored directories
				return fp.SkipDir
			}
			if p.config.ExcludeTests && p.config.IsTestDirectory(info.Name()) {
				//skip test directories if we're excluding tests
				return fp.SkipDir
			}

			wg.Add(1)
			go func() {
				defer wg.Done()
				p.ParseFile(path)
			}()

			return nil
		})

	wg.Wait()           //wait for the whole scan to finish
	close(p.resultChan) //tell the result builder we're done
	<-p.resultBuildDone //wait till result builder is done
	return err
}

// ParseFile parses the given file (if possible) and collects potential credentials
func (p *Parser) ParseFile(filepath string) {
	switch {
	case p.isParsableGoFile(filepath):
		p.parseGoFile(filepath)
	case p.isParsableJSONFile(filepath):
		p.parseJSONFile(filepath)
	case p.isParsableXMLFile(filepath):
		p.parseXMLFile(filepath)
	case p.isParsableYamlFile(filepath):
		p.parseYamlFile(filepath)
	case p.isParsablePhpFile(filepath):
		p.parsePhpFile(filepath)
	case p.isParsablePropertiesFile(filepath):
		p.parsePropertiesFile(filepath)
		fallthrough
	case p.isParsablePrivateKeyFile(filepath):
		p.parsePrivateKeyFile(filepath)
	case p.isParsableGenericFile(filepath):
		p.parseGenericFile(filepath)
	}
}

func (p *Parser) isPossiblyCredentialsVariable(varName string, value string) bool {
	// no point in considering empty values
	if len(value) < p.config.MinPasswordLength {
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

func (p *Parser) isPossiblyCredentialValue(v string) (bool, string) {
	// no point in considering empty values
	if len(v) < p.config.MinPasswordLength {
		return false, ""
	}

	// exclude any variables whose value is in our exclusion list (this would include things like defaults and test values)
	for _, m := range p.valueExcludeMatchers {
		if m.MatchString(v) {
			return false, ""
		}
	}

	// include anything in our value inclusion list. This would include things like postgres uris regardless of the variable name
	for n, m := range p.valueIncludeMatchers {
		if m.MatchString(v) {
			return true, n
		}
	}

	return false, ""
}

func getFileNameAndExtension(filepath string) (string, string) {
	extension := fp.Ext(filepath)
	dir := fp.Dir(filepath)

	name := strings.TrimPrefix(filepath, dir)
	name = strings.TrimPrefix(name, "/")
	name = strings.TrimSuffix(name, extension)

	return name, extension
}
