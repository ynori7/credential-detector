package parser

import (
	"io/ioutil"
	"log"
	"reflect"
	"strings"

	"github.com/ynori7/credential-detector/config"
	"gopkg.in/yaml.v3"
)

const (
	yamlSuffix      = ".yaml"
	yamlShortSuffix = ".yml"
)

func (p *Parser) isParsableYamlFile(filepath string) bool {
	_, ok := p.scanTypes[config.ScanTypeYaml]

	_, extension := getFileNameAndExtension(filepath)

	return ok && (extension == yamlSuffix || extension == yamlShortSuffix)
}

func (p *Parser) parseYamlFile(filepath string) {
	yamlData := make(map[string]interface{})

	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		if p.config.Verbose {
			log.Printf("could not parse %s: %v", filepath, err)
		}
		return
	}

	// Try to fix yaml files that have placeholders with % signs
	lines := strings.Split(string(data), "\n")
	for i, l := range lines {
		l2 := strings.SplitN(l, ":", 2)
		if len(l2) < 2 {
			continue
		}
		l2[1] = strings.TrimSpace(l2[1])
		if strings.HasPrefix(l2[1], "%") {
			lines[i] = l2[0] + `: "` + l2[1] + `"`
		}
	}

	err = yaml.Unmarshal([]byte(strings.Join(lines, "\n")), &yamlData)
	if err != nil {
		if p.config.Verbose {
			log.Printf("unmarshal yaml from %s: %v", filepath, err)
		}
		return
	}

	p.walkYamlMap(filepath, yamlData)
}

func (p *Parser) walkYamlMap(filepath string, m map[string]interface{}) {
	for k, v := range m {
		if reflect.TypeOf(v) == nil {
			continue
		}
		switch reflect.TypeOf(v).Kind() {
		case reflect.String:
			if p.isPossiblyCredentialsVariable(k, v.(string)) {
				p.resultChan <- Result{
					File:  filepath,
					Type:  TypeYamlVariable,
					Name:  k,
					Value: v.(string),
				}
			}
		case reflect.Slice:
			p.parseYamlSlice(filepath, k, v)
		case reflect.Map:
			if v2, ok := v.(map[string]interface{}); ok {
				if len(v2) > 0 {
					p.walkYamlMap(filepath, v2)
				}
			}
		}
	}
}

func (p *Parser) parseYamlSlice(filepath string, k string, v interface{}) {
	s := reflect.ValueOf(v)
	for i := 0; i < s.Len(); i++ {
		switch v2 := s.Index(i).Interface().(type) {
		case string:
			if ok, credType := p.isPossiblyCredentialValue(v2); ok {
				p.resultChan <- Result{
					File:           filepath,
					Type:           TypeYamlListVal,
					Name:           k,
					Value:          v2,
					CredentialType: credType,
				}
			}
		case map[string]interface{}:
			v3 := make(map[string]interface{})
			for i, j := range v2 {
				v3[i] = j
			}
			p.walkYamlMap(filepath, v3)
		}
	}
}
