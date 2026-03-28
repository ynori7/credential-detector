package parser

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
	"github.com/ynori7/credential-detector/config"
)

const (
	jsFileExtension  = ".js"
	mjsFileExtension = ".mjs"
	cjsFileExtension = ".cjs"
)

const minifiedLineThreshold = 500

var (
	// matches: var|const|let name = "value"
	jsVarDeclPattern = regexp.MustCompile(`^\s*(?:var|const|let|export\s+(?:default\s+)?(?:const|let|var))\s+(\w+)\s*=\s*(.+)`)

	// matches: module.exports.name = "value" or exports.name = "value"
	jsExportsPattern = regexp.MustCompile(`^\s*(?:module\.)?exports\.(\w+)\s*=\s*(.+)`)

	// matches: key: "value" (object property)
	jsObjectPropertyPattern = regexp.MustCompile(`^\s*(\w+)\s*:\s*(.+?)(?:,\s*)?$`)
)

func (p *Parser) isParsableJavaScriptFile(filepath string) bool {
	if _, ok := p.scanTypes[config.ScanTypeJavaScript]; !ok {
		return false
	}

	_, extension := getFileNameAndExtension(filepath)
	return extension == jsFileExtension || extension == mjsFileExtension || extension == cjsFileExtension
}

func (p *Parser) parseJavaScriptFile(filepath string) {
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

	p.parseJavaScriptContent(filepath, content, 0)
}

// parseJavaScriptContent parses JavaScript content for credentials.
// lineOffset is added to line numbers (used by HTML parser to report correct lines).
func (p *Parser) parseJavaScriptContent(filepath string, content string, lineOffset int) {
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

		if p.parseJSVarDeclaration(filepath, trimmedLine, lineNumber+lineOffset) {
			// handled
		} else if p.parseJSExportsAssignment(filepath, trimmedLine, lineNumber+lineOffset) {
			// handled
		} else if strings.HasPrefix(trimmedLine, "//") { // single-line comment
			if !p.config.ExcludeComments {
				if isPossibleCredVal, credType := p.isPossiblyCredentialValue(trimmedLine); isPossibleCredVal {
					p.resultChan <- Result{
						File:           filepath,
						Type:           TypeJSComment,
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
							Type:           TypeJSComment,
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
		} else if endsWithOpenBrace(trimmedLine) { // potential object literal — collect and parse as JSON
			block, newLineNumber, err2 := p.collectJSObjectBlock(reader, trimmedLine, lineNumber)
			if block != "" {
				p.tryParseJSObjectAsJSON(filepath, block)
			}
			lineNumber = newLineNumber
			if err2 != nil {
				return
			}
		} else if endsWithOpenBracket(trimmedLine) { // potential array literal — collect and parse as JSON
			block, newLineNumber, err2 := p.collectJSArrayBlock(reader, trimmedLine, lineNumber)
			if block != "" {
				p.tryParseJSArrayAsJSON(filepath, block)
			}
			lineNumber = newLineNumber
			if err2 != nil {
				return
			}
		} else if p.parseJSObjectProperty(filepath, trimmedLine, lineNumber+lineOffset) {
			// handled
		} else { // full-line scan for credential values
			if isPossibleCredVal, credType := p.isPossiblyCredentialValue(trimmedLine); isPossibleCredVal {
				p.resultChan <- Result{
					File:           filepath,
					Type:           TypeJSOther,
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

func (p *Parser) parseJSVarDeclaration(filepath string, line string, lineNumber int) bool {
	matches := jsVarDeclPattern.FindStringSubmatch(line)
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
			Type:  TypeJSVariable,
			Line:  lineNumber,
			Name:  varName,
			Value: valStr,
		}
	}
	return true
}

func (p *Parser) parseJSExportsAssignment(filepath string, line string, lineNumber int) bool {
	matches := jsExportsPattern.FindStringSubmatch(line)
	if matches == nil {
		return false
	}

	varName := matches[1]
	valStr := trimSemiColon(strings.TrimSpace(matches[2]))
	valueWithoutQuotes := trimQuotes(valStr)

	if valStr == valueWithoutQuotes {
		return false
	}

	if p.isPossiblyCredentialsVariable(varName, valueWithoutQuotes) {
		p.resultChan <- Result{
			File:  filepath,
			Type:  TypeJSVariable,
			Line:  lineNumber,
			Name:  varName,
			Value: valStr,
		}
	}
	return true
}

func (p *Parser) parseJSObjectProperty(filepath string, line string, lineNumber int) bool {
	matches := jsObjectPropertyPattern.FindStringSubmatch(line)
	if matches == nil {
		return false
	}

	varName := matches[1]
	valStr := trimSemiColon(strings.TrimSpace(matches[2]))
	valueWithoutQuotes := trimQuotes(valStr)

	if valStr == valueWithoutQuotes {
		return false
	}

	if p.isPossiblyCredentialsVariable(varName, valueWithoutQuotes) {
		p.resultChan <- Result{
			File:  filepath,
			Type:  TypeJSVariable,
			Line:  lineNumber,
			Name:  varName,
			Value: valStr,
		}
	}
	return true
}

// isMinifiedJS returns true if any line in the data exceeds the minified threshold.
func isMinifiedJS(data []byte) bool {
	for _, line := range bytes.SplitN(data, []byte("\n"), -1) {
		if len(line) > minifiedLineThreshold {
			return true
		}
	}
	return false
}

// unminifyJS uses the tdewolff JS lexer to tokenize minified JS and insert newlines
// after semicolons and closing braces, producing a more readable version.
func unminifyJS(data []byte) string {
	input := parse.NewInputBytes(data)
	lexer := js.NewLexer(input)

	var buf bytes.Buffer
	for {
		tt, text := lexer.Next()
		if tt == js.ErrorToken {
			if lexer.Err() == io.EOF {
				break
			}
			// on error, write remaining text and stop
			buf.Write(text)
			break
		}

		buf.Write(text)

		if tt == js.SemicolonToken || tt == js.CloseBraceToken || tt == js.OpenBraceToken || tt == js.CommaToken {
			buf.WriteByte('\n')
		}
	}

	return buf.String()
}

// endsWithOpenBrace checks if a trimmed line ends with '{', indicating the start of an object literal.
// It skips lines that are control flow statements.
func endsWithOpenBrace(trimmedLine string) bool {
	if !strings.HasSuffix(trimmedLine, "{") {
		return false
	}
	// Skip control flow statements — these are not object literals
	for _, prefix := range []string{"if ", "if(", "else", "for ", "for(", "while ", "while(", "switch ", "switch(", "function ", "function(", "try", "catch", "class "} {
		if strings.HasPrefix(trimmedLine, prefix) {
			return false
		}
	}
	return true
}

// endsWithOpenBracket checks if a trimmed line ends with '[', indicating the start of an array literal.
func endsWithOpenBracket(trimmedLine string) bool {
	return strings.HasSuffix(trimmedLine, "[")
}

// collectJSObjectBlock reads lines from the reader, accumulating them into a block
// starting from the opening '{'. It tracks brace depth to find the matching '}'.
// Returns the collected block, the updated line number, and any read error.
func (p *Parser) collectJSObjectBlock(reader *bufio.Reader, firstLine string, lineNumber int) (string, int, error) {
	// Extract just the object part (from the '{')
	braceIdx := strings.LastIndex(firstLine, "{")
	if braceIdx < 0 {
		return "", lineNumber, nil
	}

	var lines []string
	lines = append(lines, firstLine[braceIdx:])

	depth := 1
	for depth > 0 {
		next, err := reader.ReadString('\n')
		next = strings.TrimSpace(next)
		lineNumber++

		for _, ch := range next {
			if ch == '{' {
				depth++
			} else if ch == '}' {
				depth--
			}
		}

		// When we reach the closing brace, trim everything after it
		if depth == 0 {
			if closingIdx := strings.LastIndex(next, "}"); closingIdx >= 0 {
				next = next[:closingIdx+1]
			}
		}
		lines = append(lines, next)

		if err != nil {
			return strings.Join(lines, "\n"), lineNumber, err
		}
	}
	return strings.Join(lines, "\n"), lineNumber, nil
}

// collectJSArrayBlock reads lines from the reader, accumulating them into a block
// starting from the opening '['. It tracks bracket depth to find the matching ']'.
func (p *Parser) collectJSArrayBlock(reader *bufio.Reader, firstLine string, lineNumber int) (string, int, error) {
	bracketIdx := strings.LastIndex(firstLine, "[")
	if bracketIdx < 0 {
		return "", lineNumber, nil
	}

	var lines []string
	lines = append(lines, firstLine[bracketIdx:])

	depth := 1
	for depth > 0 {
		next, err := reader.ReadString('\n')
		next = strings.TrimSpace(next)
		lineNumber++

		for _, ch := range next {
			if ch == '[' {
				depth++
			} else if ch == ']' {
				depth--
			}
		}

		if depth == 0 {
			if closingIdx := strings.LastIndex(next, "]"); closingIdx >= 0 {
				next = next[:closingIdx+1]
			}
		}
		lines = append(lines, next)

		if err != nil {
			return strings.Join(lines, "\n"), lineNumber, err
		}
	}
	return strings.Join(lines, "\n"), lineNumber, nil
}

// jsObjectToJSON normalizes a JavaScript object literal into valid JSON by:
// - quoting unquoted keys
// - converting single quotes to double quotes on values
// - removing trailing commas
var jsUnquotedKeyPattern = regexp.MustCompile(`(?m)(^|[{,])\s*(\w+)\s*:`)

func jsObjectToJSON(block string) string {
	// Replace single-quoted string values with double-quoted
	block = strings.ReplaceAll(block, "'", "\"")
	// Remove trailing commas before } or ]
	block = regexp.MustCompile(`,\s*([}\]])`).ReplaceAllString(block, "$1")
	// Quote unquoted keys: word: -> "word":
	block = jsUnquotedKeyPattern.ReplaceAllStringFunc(block, func(match string) string {
		return jsUnquotedKeyPattern.ReplaceAllString(match, `${1}"${2}":`)
	})
	return block
}

// tryParseJSObjectAsJSON attempts to normalize a JS object block to JSON and walk it
// through the existing JSON map walker for credential detection.
func (p *Parser) tryParseJSObjectAsJSON(filepath string, block string) {
	jsonStr := jsObjectToJSON(block)

	var jsonData map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &jsonData); err != nil {
		return // not valid JSON after normalization — skip silently
	}

	p.walkJSONMap(filepath, jsonData)
}

// tryParseJSArrayAsJSON attempts to normalize a JS array block to JSON and walk it
// through the existing JSON slice walker for credential detection.
func (p *Parser) tryParseJSArrayAsJSON(filepath string, block string) {
	jsonStr := jsObjectToJSON(block)

	var jsonData []interface{}
	if err := json.Unmarshal([]byte(jsonStr), &jsonData); err != nil {
		return
	}

	p.parseJSONSlice(filepath, "", jsonData)
}
