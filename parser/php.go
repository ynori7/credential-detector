package parser

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/ynori7/credential-detector/config"
)

const (
	phpFileExtension = ".php"
	phpTestSuffix    = "Test"
)

func (p *Parser) isParsablePhpFile(filepath string) bool {
	if _, ok := p.scanTypes[config.ScanTypePHP]; !ok {
		return false
	}

	name, extension := getFileNameAndExtension(filepath)
	if extension == phpFileExtension {
		if strings.HasSuffix(name, phpTestSuffix) && p.config.ExcludeTests {
			return false
		}

		return true
	}

	return extension == phpFileExtension
}

func (p *Parser) parsePhpFile(filepath string) {
	if len(filepath) == 0 {
		return
	}

	file, err := os.Open(filepath)
	if err != nil {
		return
	}
	defer file.Close()

	lineNumber := 1
	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadString('\n')

		trimmedLine := strings.TrimSpace(line)

		//It's an assignment
		if strings.HasPrefix(trimmedLine, "$") {
			varName, val, heredocID, newLineNumber, err2 := parsePhpAssignment(reader, trimmedLine, lineNumber)
			if varName != "" && val != "" {
				if p.isPossiblyCredentialsVariable(strings.TrimPrefix(varName, "$"), strings.Trim(val, "'\"")) {
					if heredocID != "" {
						p.Results = append(p.Results, Result{
							File:  filepath,
							Type:  TypePHPHeredoc,
							Line:  lineNumber,
							Name:  varName,
							Value: fmt.Sprintf("<<<%s\n%s\n%s", heredocID, val, heredocID),
						})
					} else {
						p.Results = append(p.Results, Result{
							File:  filepath,
							Type:  TypePHPVariable,
							Line:  lineNumber,
							Name:  varName,
							Value: val,
						})
					}
				}
			}
			lineNumber = newLineNumber

			if err2 != nil {
				return
			}
		} else if strings.HasPrefix(trimmedLine, "const ") { //It's a constant
			varName, val, _, newLineNumber, err2 := parsePhpAssignment(reader, trimmedLine, lineNumber)
			if varName != "" && val != "" {
				if p.isPossiblyCredentialsVariable(strings.TrimPrefix(varName, "const "), strings.Trim(val, "'\"")) {
					p.Results = append(p.Results, Result{
						File:  filepath,
						Type:  TypePHPConstant,
						Line:  lineNumber,
						Name:  varName,
						Value: val,
					})
				}
			}
			lineNumber = newLineNumber

			if err2 != nil {
				return
			}
		} else if strings.HasPrefix(trimmedLine, "//") { //It's a comment
			if !p.config.ExcludeComments {
				if p.isPossiblyCredentialValue(line) {
					p.Results = append(p.Results, Result{
						File:  filepath,
						Type:  TypePHPComment,
						Line:  lineNumber,
						Name:  "",
						Value: trimmedLine,
					})
				}
			}
		} else if strings.HasPrefix(trimmedLine, "/*") { //It's a multiline comment
			if !p.config.ExcludeComments {
				commentBody, newLineNumber, err2 := parseMultilinePhpComment(reader, trimmedLine, lineNumber)
				if commentBody != "" && p.isPossiblyCredentialValue(commentBody) {
					p.Results = append(p.Results, Result{
						File:  filepath,
						Type:  TypePHPComment,
						Line:  lineNumber,
						Name:  "",
						Value: commentBody,
					})
					lineNumber = newLineNumber

					if err2 != nil {
						return
					}
				}
			}
		}

		if err != nil {
			return
		}

		lineNumber++
	}
}

//returns variable name, value, heredoc idenfifier (if present), line number, and error (if present)
func parsePhpAssignment(r *bufio.Reader, line string, lineNumber int) (string, string, string, int, error) {
	var (
		name        string
		valPartsStr string
	)

	parts := strings.SplitN(line, "=", 2)
	if len(parts) == 2 {
		name = strings.TrimSpace(parts[0])
		valPartsStr = strings.TrimSpace(parts[1])

		// cut off comments
		valPartsStr = trimAfter(valPartsStr, "//")
		valPartsStr = trimAfter(valPartsStr, "/*")

		if strings.Contains(valPartsStr, ";") && (strings.HasPrefix(valPartsStr, "'") || strings.HasPrefix(valPartsStr, "\"")) {
			// normal assignment
			// maybe not ideal, but it'll consider a value of "string" . $var but not $var . "string"
			return name, strings.TrimSpace(valPartsStr[0:strings.LastIndex(valPartsStr, ";")]), "", lineNumber, nil
		}

		if strings.HasPrefix(valPartsStr, "<<<") {
			//heredoc
			identifier := strings.ReplaceAll(strings.TrimPrefix(valPartsStr, "<<<"), "'", "")
			value := ""

			for {
				line2, err := r.ReadString('\n')
				if strings.HasPrefix(strings.TrimSpace(line2), identifier+";") {
					return name, strings.TrimSuffix(value, "\n"), identifier, lineNumber + 1, err
				}

				value += line2

				if err != nil {
					return "", "", "", lineNumber, err
				}

				lineNumber++
			}
		}
	}

	return "", "", "", lineNumber, nil
}

//returns the comment body, line number, and error (if present)
func parseMultilinePhpComment(r *bufio.Reader, line string, lineNumber int) (string, int, error) {
	if strings.Contains(line, "*/") {
		return line, lineNumber, nil
	}

	lines := []string{line}
	for {
		line2, err := r.ReadString('\n')
		line2 = strings.TrimSpace(line2)
		lines = append(lines, line2)

		if strings.Contains(line2, "*/") {
			return strings.Join(lines, "\n"), lineNumber + 1, err
		}

		if err != nil {
			return "", lineNumber, err
		}

		lineNumber++
	}
}

func trimAfter(s string, tok string) string {
	lastIndex := strings.LastIndex(s, tok)
	if lastIndex < 0 {
		return s
	}

	return s[0:lastIndex]
}