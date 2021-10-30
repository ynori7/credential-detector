package parser

import (
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"strings"

	"github.com/ynori7/credential-detector/config"
)

const (
	goSuffix     = ".go"
	goTestSuffix = "_test"
)

func (p *Parser) isParsableGoFile(filepath string) bool {
	if _, ok := p.scanTypes[config.ScanTypeGo]; !ok {
		return false
	}

	name, extension := getFileNameAndExtension(filepath)

	if extension == goSuffix {
		if strings.HasSuffix(name, goTestSuffix) && p.config.ExcludeTests {
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

	foundLines := map[int]struct{}{}

	for _, d := range f.Decls {
		switch decl := d.(type) {
		case *ast.FuncDecl:
			//ignore
		case *ast.GenDecl:
			p.parseDeclaration(decl, filepath, fs, foundLines)
		default:
			//ignore
		}
	}

	if !p.config.ExcludeComments {
		for _, d := range f.Comments {
			if ok, credType := p.isPossiblyCredentialsInComment(d); ok {
				p.resultChan <- Result{
					File:           filepath,
					Type:           TypeGoComment,
					Line:           fs.Position(d.Pos()).Line,
					Name:           "",
					Value:          p.buildCommentString(d.List),
					CredentialType: credType,
				}
			}
			foundLines[fs.Position(d.Pos()).Line] = struct{}{}
		}
	}

	//Now scan the raw file line-by-line, just looking for potential value matches
	p.parseGoFileLineByLine(filepath, foundLines)
}

func (p *Parser) parseGoFileLineByLine(filepath string, foundLines map[int]struct{}) {
	file, err := os.Open(filepath)
	if err != nil {
		return
	}
	defer file.Close()

	lineNumber := 1
	inComment := false

	reader := getReader(file)
	defer putReader(reader)

	var (
		line              string
		alreadyFound      bool
		isPossibleCredVal bool
		credType          string
	)
	for {
		line, err = reader.ReadString('\n')

		//we already looked at comments
		line = strings.Split(line, "//")[0]
		if strings.Contains(line, "/*") {
			inComment = true
		}
		if strings.Contains(line, "*/") {
			inComment = false
		}

		_, alreadyFound = foundLines[lineNumber]

		isPossibleCredVal, credType = p.isPossiblyCredentialValue(line)
		if isPossibleCredVal && !alreadyFound && !inComment {
			p.resultChan <- Result{
				File:           filepath,
				Type:           TypeGoOther,
				Line:           lineNumber,
				Name:           "",
				Value:          strings.TrimSpace(line),
				CredentialType: credType,
			}
		}

		if err != nil {
			return
		}

		lineNumber++
	}
}

func (p *Parser) parseDeclaration(decl *ast.GenDecl, filepath string, fs *token.FileSet, foundLines map[int]struct{}) {
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
						p.resultChan <- Result{
							File:  filepath,
							Type:  TypeGoVariable,
							Line:  fs.Position(val.Pos()).Line,
							Name:  id.Name,
							Value: val.Value,
						}
						foundLines[fs.Position(val.Pos()).Line] = struct{}{}
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

func (p *Parser) isPossiblyCredentialsInComment(value *ast.CommentGroup) (bool, string) {
	return p.isPossiblyCredentialValue(value.Text())
}

func (p *Parser) buildCommentString(comments []*ast.Comment) string {
	lines := make([]string, len(comments))
	for i, l := range comments {
		lines[i] = l.Text
	}

	return strings.Join(lines, "\n")
}
