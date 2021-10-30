package parser

import (
	"github.com/ynori7/credential-detector/config"
	"os"
	"strings"
)

func (p *Parser) isParsableGenericFile(filepath string) bool {
	if _, ok := p.scanTypes[config.ScanTypeGeneric]; !ok {
		return false
	}

	_, extension := getFileNameAndExtension(filepath)
	extension = strings.TrimPrefix(extension, ".")

	for _, ext := range p.config.GenericFileExtensions {
		if ext == strings.ToLower(extension) {
			return true
		}
	}

	return false
}

func (p *Parser) parseGenericFile(filepath string) {
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
		ok       bool
		credType string
	)
	for {
		line, err = reader.ReadString('\n')
		line = strings.TrimSpace(line)

		if ok, credType = p.isPossiblyCredentialValue(line); ok {
			p.resultChan <- Result{
				File:           filepath,
				Type:           TypeGeneric,
				Line:           lineNumber,
				Name:           "",
				Value:          line,
				CredentialType: credType,
			}
		}

		if err != nil {
			return
		}

		lineNumber++
	}
}
