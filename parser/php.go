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

	return false
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
	reader := getReader(file)
	defer putReader(reader)

	var (
		line, trimmedLine string
		isPossibleCredVal bool
		credType          string
	)
	var (
		varName, val, heredocID string
		commentBody             string
		newLineNumber           int
		err2                    error
	)
	for {
		line, err = reader.ReadString('\n')
		trimmedLine = strings.TrimSpace(line)

		//It's an assignment
		if strings.HasPrefix(trimmedLine, "$") {
			varName, val, heredocID, newLineNumber, err2 = parsePhpAssignment(reader, trimmedLine, lineNumber)
			if varName != "" && val != "" {
				if p.isPossiblyCredentialsVariable(strings.TrimPrefix(varName, "$"), strings.Trim(val, "'\"")) {
					if heredocID != "" {
						p.resultChan <- Result{
							File:  filepath,
							Type:  TypePHPHeredoc,
							Line:  lineNumber,
							Name:  varName,
							Value: fmt.Sprintf("<<<%s\n%s\n%s", heredocID, val, heredocID),
						}
					} else {
						p.resultChan <- Result{
							File:  filepath,
							Type:  TypePHPVariable,
							Line:  lineNumber,
							Name:  varName,
							Value: val,
						}
					}
				}
			}
			lineNumber = newLineNumber

			if err2 != nil {
				return
			}
		} else if strings.HasPrefix(trimmedLine, "private ") || strings.HasPrefix(trimmedLine, "protected ") ||
			strings.HasPrefix(trimmedLine, "public ") { //It's a class variable

			varName, val, _, newLineNumber, err2 = parsePhpAssignment(reader, trimmedLine, lineNumber)
			if varName != "" && val != "" {
				if p.isPossiblyCredentialsVariable(trimDeclarationPrefix(varName), strings.Trim(val, "'\"")) {
					p.resultChan <- Result{
						File:  filepath,
						Type:  TypePHPVariable,
						Line:  lineNumber,
						Name:  varName,
						Value: val,
					}
				}
			}
			lineNumber = newLineNumber

			if err2 != nil {
				return
			}
		} else if strings.HasPrefix(trimmedLine, "const ") { //It's a constant
			varName, val, _, newLineNumber, err2 = parsePhpAssignment(reader, trimmedLine, lineNumber)
			if varName != "" && val != "" {
				if p.isPossiblyCredentialsVariable(trimDeclarationPrefix(varName), strings.Trim(val, "'\"")) {
					p.resultChan <- Result{
						File:  filepath,
						Type:  TypePHPConstant,
						Line:  lineNumber,
						Name:  varName,
						Value: val,
					}
				}
			}
			lineNumber = newLineNumber

			if err2 != nil {
				return
			}
		} else if strings.HasPrefix(trimmedLine, "define") { //It's a named constant
			varName, val = parsePhpDefineCall(trimmedLine)
			if varName != "" && val != "" {
				if p.isPossiblyCredentialsVariable(trimDeclarationPrefix(varName), strings.Trim(val, "'\"")) {
					p.resultChan <- Result{
						File:  filepath,
						Type:  TypePHPConstant,
						Line:  lineNumber,
						Name:  varName,
						Value: val,
					}
				}
			}
		} else if strings.HasPrefix(trimmedLine, "//") { //It's a comment
			if !p.config.ExcludeComments {
				if isPossibleCredVal, credType = p.isPossiblyCredentialValue(line); isPossibleCredVal {
					p.resultChan <- Result{
						File:           filepath,
						Type:           TypePHPComment,
						Line:           lineNumber,
						Name:           "",
						Value:          trimmedLine,
						CredentialType: credType,
					}
				}
			}
		} else if strings.HasPrefix(trimmedLine, "/*") { //It's a multiline comment
			if !p.config.ExcludeComments {
				commentBody, newLineNumber, err2 = parseMultilineCStyleComment(reader, trimmedLine, lineNumber)
				isPossibleCredVal, credType = p.isPossiblyCredentialValue(commentBody)
				if commentBody != "" && isPossibleCredVal {
					p.resultChan <- Result{
						File:           filepath,
						Type:           TypePHPComment,
						Line:           lineNumber,
						Name:           "",
						Value:          commentBody,
						CredentialType: credType,
					}

					if err2 != nil {
						return
					}
				}

				lineNumber = newLineNumber
			}
		} else { //scan the whole line for possible value matches
			if isPossibleCredVal, credType = p.isPossiblyCredentialValue(trimmedLine); isPossibleCredVal {
				p.resultChan <- Result{
					File:           filepath,
					Type:           TypePHPOther,
					Line:           lineNumber,
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
		valPartsStr = trimAfter(valPartsStr, "//") //Note that this is flawed if the comment is in a string
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

//returns const name and value if valid
func parsePhpDefineCall(line string) (string, string) {
	paramBody := functionRegex.FindStringSubmatch(line) //Doesn't work when it's split across multiple lines
	if len(paramBody) != 2 {
		return "", ""
	}

	//Naive implementation since the params could have commas in them, but it's not worth the extra effort of parsing char-by-char
	params := strings.Split(paramBody[1], ",")
	if len(params) < 2 {
		return "", ""
	}

	return strings.Trim(params[0], "\"' "), strings.TrimSpace(params[1]) //the quotes are trimmed in the value later
}

func trimAfter(s string, tok string) string {
	lastIndex := strings.LastIndex(s, tok)
	if lastIndex < 0 {
		return s
	}

	return s[0:lastIndex]
}

func trimDeclarationPrefix(s string) string {
	s = strings.TrimPrefix(s, "const ")
	s = strings.TrimPrefix(s, "private ")
	s = strings.TrimPrefix(s, "protected ")
	s = strings.TrimPrefix(s, "public ")
	return s
}
