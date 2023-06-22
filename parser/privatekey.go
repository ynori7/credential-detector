package parser

import (
	"bufio"
	"os"
	"strings"

	"github.com/ynori7/credential-detector/config"
)

var privateKeyExtensions = map[string]struct{}{
	".spc":  {},
	".p7a":  {},
	".p7b":  {},
	".p7c":  {},
	".p8":   {},
	".p12":  {},
	".pfx":  {},
	".key":  {},
	".cert": {},
	".cer":  {},
	".der":  {},
	".pem":  {},
	"":      {}, //we'll also try files with no extension such as "id_rsa"
}

var privateKeyHeaders = []string{
	"-----BEGIN PRIVATE KEY-----",
	"-----BEGIN CERTIFICATE-----",
	"-----BEGIN RSA PRIVATE KEY-----",
	"-----BEGIN ENCRYPTED PRIVATE KEY-----",
}

func (p *Parser) isParsablePrivateKeyFile(filepath string) bool {
	if _, ok := p.scanTypes[config.ScanTypePrivateKey]; !ok {
		return false
	}

	_, extension := getFileNameAndExtension(filepath)
	if _, ok := privateKeyExtensions[extension]; ok {
		return true
	}

	return false
}

func (p *Parser) parsePrivateKeyFile(filepath string) {
	if len(filepath) == 0 {
		return
	}

	file, err := os.Open(filepath)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan()

	firstLine := strings.TrimSpace(scanner.Text())

	for _, h := range privateKeyHeaders {
		if firstLine == h {
			p.resultChan <- Result{
				File:  filepath,
				Type:  TypePrivateKey,
				Line:  1,
				Name:  "",
				Value: firstLine,
			}
		}
	}
}
