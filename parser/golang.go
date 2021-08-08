package parser

import (
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"strings"
)

const (
	GoSuffix     = ".go"
	GoTestSuffix = "_test.go"
)

func (p *Parser) isParsableGoFile(filepath string) bool {
	if strings.HasSuffix(filepath, GoSuffix) {
		if strings.HasSuffix(filepath, GoTestSuffix) && p.config.ExcludeTests {
			return false
		}

		return true
	}

	return false
}

func (p *Parser) parseGoFile(filepath string) {
	fs := token.NewFileSet()

	f, err := parser.ParseFile(fs, filepath, nil, parser.ParseComments)
	if err != nil {
		if p.config.Verbose {
			log.Printf("could not parse %s: %v", filepath, err)
		}
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
					Type:  TypeGoComment,
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
					if p.isPossiblyCredentialsInGoVariable(id.Name, val) {
						p.Results = append(p.Results, Result{
							File:  filepath,
							Type:  TypeGoVariable,
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

func (p *Parser) isPossiblyCredentialsInGoVariable(varName string, value *ast.BasicLit) bool {
	// exclude non-strings and empty values
	if value.Kind != token.STRING || value.Value == `""` {
		return false
	}

	// remove quotes around the string
	val := value.Value[1 : len(value.Value)-1]

	return p.isPossiblyCredentialsVariable(varName, val)
}

func (p *Parser) isPossiblyCredentialsInComment(value *ast.CommentGroup) bool {
	return p.isPossiblyCredentialValue(value.Text())
}

func (p *Parser) buildCommentString(comments []*ast.Comment) string {
	lines := make([]string, len(comments))
	for i, l := range comments {
		lines[i] = l.Text
	}

	return strings.Join(lines, "\n")
}
