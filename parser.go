package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"regexp"
	"strings"
)

const (
	GoSuffix   = ".go"
	TestSuffix = "_test.go"
)

type Parser struct {
	config Config

	variableNameMatcher          *regexp.Regexp
	variableNameExclusionMatcher *regexp.Regexp
	valueIncludeMatchers         []*regexp.Regexp
	valueExcludeMatchers         []*regexp.Regexp

	Results []Result
}

type Result struct {
	File  string
	Line  int
	Name  string
	Value string
}

func NewParser(conf Config) Parser {
	parser := Parser{
		config:                       conf,
		variableNameMatcher:          regexp.MustCompile(conf.VariableNamePattern),
		variableNameExclusionMatcher: regexp.MustCompile(conf.VariableNameExclusionPattern),
		valueIncludeMatchers:         make([]*regexp.Regexp, len(conf.ValueMatchPatterns)),
		valueExcludeMatchers:         make([]*regexp.Regexp, len(conf.ValueExcludePatterns)),
		Results:                      make([]Result, 0),
	}

	for k, v := range conf.ValueMatchPatterns {
		parser.valueIncludeMatchers[k] = regexp.MustCompile(v)
	}

	for k, v := range conf.ValueExcludePatterns {
		parser.valueExcludeMatchers[k] = regexp.MustCompile(v)
	}

	return parser
}

func (p *Parser) IsPossiblyCredentials(varName string, value *ast.BasicLit) bool {
	// exclude non-strings and empty values
	if value.Kind != token.STRING || value.Value == `""` {
		return false
	}

	// remove quotes around the string
	val := value.Value[1 : len(value.Value)-1]

	// exclude any variables whose value is in our exclusion list (this would include things like defaults and test values)
	for _, m := range p.valueExcludeMatchers {
		if m.MatchString(val) {
			return false
		}
	}

	// include anything in our value inclusion list. This would include things like postgres uris regardless of the variable name
	for _, m := range p.valueIncludeMatchers {
		if m.MatchString(val) {
			return true
		}
	}

	// if exclusions are defined for variable names, check
	if p.config.VariableNameExclusionPattern != "" && p.variableNameExclusionMatcher.MatchString(varName) {
		return false
	}

	// include variables which have potentially suspicious names, but only if the value does not also match (to exclude constants like const Token = "token")
	if p.variableNameMatcher.MatchString(varName) && !p.variableNameMatcher.MatchString(val) {
		return true
	}

	return false
}

func (p *Parser) ParseFile(filepath string) {
	if !strings.HasSuffix(filepath, GoSuffix) {
		return
	}

	if strings.HasSuffix(filepath, TestSuffix) && p.config.ExcludeTests {
		return
	}

	fs := token.NewFileSet()

	f, err := parser.ParseFile(fs, filepath, nil, parser.AllErrors)
	if err != nil {
		log.Printf("could not parse %s: %v", filepath, err)
		return
	}

	for _, d := range f.Decls {
		switch decl := d.(type) {
		case *ast.FuncDecl:
			//ignore
		case *ast.GenDecl:
			p.parseDeclaration(decl, filepath, fs)
		default:
			//ignore
		}
	}
}

func (p *Parser) parseDeclaration(decl *ast.GenDecl, filepath string, fs *token.FileSet) {
	for _, spec := range decl.Specs {
		switch spec := spec.(type) {
		case *ast.ImportSpec:
			//ignore
			//fmt.Println("Import", spec.Path.Value)
		case *ast.TypeSpec:
			//ignore
			//fmt.Println("Type", spec.Name.String())
		case *ast.ValueSpec:
			for _, id := range spec.Names {
				if len(id.Obj.Decl.(*ast.ValueSpec).Values) == 0 {
					continue
				}
				switch val := id.Obj.Decl.(*ast.ValueSpec).Values[0].(type) {
				case *ast.BasicLit:
					if p.IsPossiblyCredentials(id.Name, val) {
						p.Results = append(p.Results, Result{
							File:  filepath,
							Line:  fs.Position(val.Pos()).Line,
							Name:  id.Name,
							Value: val.Value,
						})
					}
				case *ast.UnaryExpr:
					//ignore
					//fmt.Printf("Var (unaryExpr) %s: %v", id.Name, val)
				default:
					//ignore
					//fmt.Printf("Unknown token type: %s\n", decl.Tok)
				}
			}

		}
	}
}
