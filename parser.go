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

const (
	TypeComment  = "comment"
	TypeVariable = "variable"
)

type Parser struct {
	config Config

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

func NewParser(conf Config) Parser {
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
	if !strings.HasSuffix(filepath, GoSuffix) {
		return
	}

	if strings.HasSuffix(filepath, TestSuffix) && p.config.ExcludeTests {
		return
	}

	fs := token.NewFileSet()

	f, err := parser.ParseFile(fs, filepath, nil, parser.ParseComments)
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

	if !p.config.ExcludeComments {
		for _, d := range f.Comments {
			if p.isPossiblyCredentialsInComment(d) {
				p.Results = append(p.Results, Result{
					File:  filepath,
					Type:  TypeComment,
					Line:  fs.Position(d.Pos()).Line,
					Name:  "",
					Value: p.buildCommentString(d.List),
				})
			}
		}
	}
}

func (p *Parser) parseDeclaration(decl *ast.GenDecl, filepath string, fs *token.FileSet) {
	for _, spec := range decl.Specs {
		switch spec := spec.(type) {
		case *ast.ImportSpec:
			//ignore
		case *ast.TypeSpec:
			//ignore
		case *ast.ValueSpec:
			for _, id := range spec.Names {
				if len(id.Obj.Decl.(*ast.ValueSpec).Values) == 0 {
					continue
				}
				switch val := id.Obj.Decl.(*ast.ValueSpec).Values[0].(type) {
				case *ast.BasicLit:
					if p.isPossiblyCredentials(id.Name, val) {
						p.Results = append(p.Results, Result{
							File:  filepath,
							Type:  TypeVariable,
							Line:  fs.Position(val.Pos()).Line,
							Name:  id.Name,
							Value: val.Value,
						})
					}
				case *ast.UnaryExpr:
					//ignore
				default:
					//ignore
				}
			}

		}
	}
}

func (p *Parser) isPossiblyCredentials(varName string, value *ast.BasicLit) bool {
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

	for _, m := range p.variableNameMatchers {
		// include variables which have potentially suspicious names, but only if the value does not also match (to exclude constants like const Token = "token")
		if m.MatchString(varName) && !m.MatchString(val) {
			return true
		}
	}

	return false
}

func (p *Parser) isPossiblyCredentialsInComment(value *ast.CommentGroup) bool {
	for _, m := range p.valueIncludeMatchers {
		if m.MatchString(value.Text()) {
			return true
		}
	}

	return false
}

func (p *Parser) buildCommentString(comments []*ast.Comment) string {
	lines := make([]string, len(comments))
	for i, l := range comments {
		lines[i] = l.Text
	}

	return strings.Join(lines, "\n")
}