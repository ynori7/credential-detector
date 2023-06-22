package parser

import (
	"os"
	"regexp"
	"strings"

	"github.com/ynori7/credential-detector/config"
)

const bashSuffix = ".sh"

var bashDeclarationPattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*=['"].+`)

func (p *Parser) isParsableBashFile(filepath string) bool {
	if _, ok := p.scanTypes[config.ScanTypeGenericCode]; !ok {
		return false
	}

	_, extension := getFileNameAndExtension(filepath)
	return extension == bashSuffix
}

func (p *Parser) parseBashFile(filepath string) {
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

		if bashDeclarationPattern.MatchString(line) {
			parts := strings.SplitN(line, "=", 2) //there must be an = if we entered this block

			valueWithoutQuotes := trimQuotes(parts[1])
			if ok = p.isPossiblyCredentialsVariable(parts[0], valueWithoutQuotes); ok {
				p.resultChan <- Result{
					File:  filepath,
					Type:  TypeBashVariable,
					Line:  lineNumber,
					Name:  "",
					Value: line,
				}
			}
		}

		if err != nil {
			return
		}

		lineNumber++
	}
}
