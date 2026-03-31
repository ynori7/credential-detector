package parser

import (
	"os"
	"regexp"
	"strings"

	"github.com/ynori7/credential-detector/config"
)

const (
	tsFileExtension  = ".ts"
	tsxFileExtension = ".tsx"
)

var (
	// matches: var|const|let name[: Type] = "value"
	// Also handles: export [default] const|let|var name[: Type] = "value"
	tsVarDeclPattern = regexp.MustCompile(`^\s*(?:export\s+(?:default\s+)?(?:const|let|var)|var|const|let)\s+(\w+)(?:\s*:\s*[\w<>[\],\s|&?]+)?\s*=\s*(.+)`)

	// matches: [public|private|protected] [static] [readonly] name[: Type] = "value"
	tsClassPropPattern = regexp.MustCompile(`^\s*(?:(?:public|private|protected|override|static|abstract)\s+)+(?:readonly\s+)?(\w+)(?:\s*:\s*[\w<>[\],\s|&?]+)?\s*=\s*(.+)`)
)

func (p *Parser) isParsableTypeScriptFile(filepath string) bool {
	if _, ok := p.scanTypes[config.ScanTypeTypeScript]; !ok {
		return false
	}

	_, extension := getFileNameAndExtension(filepath)
	return extension == tsFileExtension || extension == tsxFileExtension
}

func (p *Parser) parseTypeScriptFile(filepath string) {
	if len(filepath) == 0 {
		return
	}

	data, err := os.ReadFile(filepath)
	if err != nil {
		return
	}

	content := string(data)
	if isMinifiedJS(data) {
		content = unminifyJS(data)
	}

	p.parseTypeScriptContent(filepath, content, 0)
}

// parseTypeScriptContent parses TypeScript content for credentials.
// lineOffset is added to line numbers (used by HTML parser to report correct lines).
func (p *Parser) parseTypeScriptContent(filepath string, content string, lineOffset int) {
	reader := getReader(strings.NewReader(content))
	defer putReader(reader)

	lineNumber := 1
	var (
		line        string
		err         error
		trimmedLine string
	)

	for {
		line, err = reader.ReadString('\n')
		trimmedLine = strings.TrimSpace(line)

		if trimmedLine == "" {
			if err != nil {
				return
			}
			lineNumber++
			continue
		}

		if p.parseTSVarDeclaration(filepath, trimmedLine, lineNumber+lineOffset) {
			// handled
		} else if p.parseTSClassProperty(filepath, trimmedLine, lineNumber+lineOffset) {
			// handled
		} else if strings.HasPrefix(trimmedLine, "//") { // single-line comment
			if !p.config.ExcludeComments {
				if isPossibleCredVal, credType := p.isPossiblyCredentialValue(trimmedLine); isPossibleCredVal {
					p.resultChan <- Result{
						File:           filepath,
						Type:           TypeTSComment,
						Line:           lineNumber + lineOffset,
						Name:           "",
						Value:          trimmedLine,
						CredentialType: credType,
					}
				}
			}
		} else if strings.HasPrefix(trimmedLine, "/*") { // multiline comment
			if !p.config.ExcludeComments {
				commentBody, newLineNumber, err2 := parseMultilineCStyleComment(reader, trimmedLine, lineNumber)
				if commentBody != "" {
					if isPossibleCredVal, credType := p.isPossiblyCredentialValue(commentBody); isPossibleCredVal {
						p.resultChan <- Result{
							File:           filepath,
							Type:           TypeTSComment,
							Line:           lineNumber + lineOffset,
							Name:           "",
							Value:          commentBody,
							CredentialType: credType,
						}
					}
				}
				lineNumber = newLineNumber
				if err2 != nil {
					return
				}
			}
		} else if endsWithOpenBrace(trimmedLine) { // potential object literal
			block, newLineNumber, err2 := p.collectJSObjectBlock(reader, trimmedLine, lineNumber)
			if block != "" {
				p.tryParseJSObjectAsJSON(filepath, block)
			}
			lineNumber = newLineNumber
			if err2 != nil {
				return
			}
		} else if endsWithOpenBracket(trimmedLine) { // potential array literal
			block, newLineNumber, err2 := p.collectJSArrayBlock(reader, trimmedLine, lineNumber)
			if block != "" {
				p.tryParseJSArrayAsJSON(filepath, block)
			}
			lineNumber = newLineNumber
			if err2 != nil {
				return
			}
		} else if p.parseTSObjectProperty(filepath, trimmedLine, lineNumber+lineOffset) {
			// handled
		} else { // full-line scan for credential values
			if isPossibleCredVal, credType := p.isPossiblyCredentialValue(trimmedLine); isPossibleCredVal {
				p.resultChan <- Result{
					File:           filepath,
					Type:           TypeTSOther,
					Line:           lineNumber + lineOffset,
					Name:           "",
					Value:          trimmedLine,
					CredentialType: credType,
				}
			}
		}

		if err != nil {
			return
		}
		lineNumber++
	}
}

func (p *Parser) parseTSVarDeclaration(filepath string, line string, lineNumber int) bool {
	matches := tsVarDeclPattern.FindStringSubmatch(line)
	if matches == nil {
		return false
	}

	varName := matches[1]
	valStr := trimSemiColon(strings.TrimSpace(matches[2]))
	valueWithoutQuotes := trimQuotes(valStr)

	if valStr == valueWithoutQuotes {
		// not a string literal assignment
		return false
	}

	if p.isPossiblyCredentialsVariable(varName, valueWithoutQuotes) {
		p.resultChan <- Result{
			File:  filepath,
			Type:  TypeTSVariable,
			Line:  lineNumber,
			Name:  varName,
			Value: valStr,
		}
	}
	return true
}

func (p *Parser) parseTSClassProperty(filepath string, line string, lineNumber int) bool {
	matches := tsClassPropPattern.FindStringSubmatch(line)
	if matches == nil {
		return false
	}

	varName := matches[1]
	valStr := trimSemiColon(strings.TrimSpace(matches[2]))
	valueWithoutQuotes := trimQuotes(valStr)

	if valStr == valueWithoutQuotes {
		// not a string literal assignment
		return false
	}

	if p.isPossiblyCredentialsVariable(varName, valueWithoutQuotes) {
		p.resultChan <- Result{
			File:  filepath,
			Type:  TypeTSVariable,
			Line:  lineNumber,
			Name:  varName,
			Value: valStr,
		}
	}
	return true
}

func (p *Parser) parseTSObjectProperty(filepath string, line string, lineNumber int) bool {
	matches := jsObjectPropertyPattern.FindStringSubmatch(line)
	if matches == nil {
		return false
	}

	varName := matches[1]
	valStr := trimSemiColon(strings.TrimSpace(matches[2]))
	valueWithoutQuotes := trimQuotes(valStr)

	if valStr == valueWithoutQuotes {
		// not a string literal assignment
		return false
	}

	if p.isPossiblyCredentialsVariable(varName, valueWithoutQuotes) {
		p.resultChan <- Result{
			File:  filepath,
			Type:  TypeTSVariable,
			Line:  lineNumber,
			Name:  varName,
			Value: valStr,
		}
	}
	return true
}
