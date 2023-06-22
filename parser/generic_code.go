package parser

import (
	"os"
	"strings"

	"github.com/ynori7/credential-detector/config"
)

var declarationPrefixes = map[string]bool{
	"public":      true,
	"private":     true,
	"protected":   true,
	"static":      true,
	"var":         true,
	"const":       true,
	"string":      true,
	"std::string": true,
	"final":       true,
}

func (p *Parser) isParsableGenericCodeFile(filepath string) bool {
	if _, ok := p.scanTypes[config.ScanTypeGenericCode]; !ok {
		return false
	}

	_, extension := getFileNameAndExtension(filepath)
	extension = strings.TrimPrefix(extension, ".")

	for _, ext := range p.config.GenericCodeFileExtensions {
		if ext == strings.ToLower(extension) {
			return true
		}
	}

	return false
}

func (p *Parser) parseGenericCodeFile(filepath string) {
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

	var line string

	var (
		ok bool
	)
	for {
		line, err = reader.ReadString('\n')
		line = strings.TrimSpace(line)

		if isVariableDeclaration(line) {
			parts := strings.SplitN(line, "=", 2) //there must be an = if we entered this block
			varNameParts := strings.Split(strings.TrimSpace(parts[0]), " ")
			varName := varNameParts[len(varNameParts)-1]
			value := trimSemiColon(strings.TrimSpace(parts[1]))

			valueWithoutQuotes := trimQuotes(value)
			if value != valueWithoutQuotes { //we only want assignments to string literals
				if ok = p.isPossiblyCredentialsVariable(varName, valueWithoutQuotes); ok {
					p.resultChan <- Result{
						File:  filepath,
						Type:  TypeGenericCode,
						Line:  lineNumber,
						Name:  "",
						Value: line,
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

func isVariableDeclaration(line string) bool {
	parts := strings.Split(line, " ")

	//check if the line starts with a potential declaration prefix
	if !declarationPrefixes[strings.ToLower(parts[0])] {
		return false
	}

	return strings.Contains(line, "=")
}
