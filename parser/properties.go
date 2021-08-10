package parser

import (
	"bufio"
	"os"
	"strings"

	"github.com/ynori7/credential-detector/config"
)

const (
	propertiesFileExtension = ".properties"
)

func (p *Parser) isParsablePropertiesFile(filepath string) bool {
	if _, ok := p.scanTypes[config.ScanTypeProperties]; !ok {
		return false
	}

	name, extension := getFileNameAndExtension(filepath)

	//consider empty file names in case the file is named something like ".env"
	return name == "" || extension == propertiesFileExtension
}

func (p *Parser) parsePropertiesFile(filepath string) {
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

		if equal := strings.Index(line, "#"); equal == 0 { // it's a comment
			if !p.config.ExcludeComments {
				if p.isPossiblyCredentialValue(line) {
					p.Results = append(p.Results, Result{
						File:  filepath,
						Type:  TypePropertiesComment,
						Line:  lineNumber,
						Name:  "",
						Value: line,
					})
				}
			}
		} else if equal := strings.Index(line, "="); equal >= 0 { // it's a property
			if key := strings.TrimSpace(line[:equal]); len(key) > 0 {
				value := ""
				if len(line) > equal {
					value = strings.TrimSpace(line[equal+1:])
				}
				if p.isPossiblyCredentialsVariable(key, value) {
					p.Results = append(p.Results, Result{
						File:  filepath,
						Type:  TypePropertiesValue,
						Line:  lineNumber,
						Name:  key,
						Value: value,
					})
				}
			}
		}

		if err != nil {
			return
		}

		lineNumber++
	}
}
