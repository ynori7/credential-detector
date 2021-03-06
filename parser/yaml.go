package parser

import (
	"fmt"
	"github.com/ynori7/credential-detector/config"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"reflect"
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

	err = yaml.Unmarshal(data, &yamlData)
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
			if v2, ok := v.(map[interface{}]interface{}); ok {
				if len(v2) > 0 {
					v3 := make(map[string]interface{})
					for i, j := range v2 {
						//use sprintf instead of type assertion because sometimes it might be an int
						v3[fmt.Sprintf("%v", i)] = j
					}
					p.walkYamlMap(filepath, v3)
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
		case map[interface{}]interface{}:
			v3 := make(map[string]interface{})
			for i, j := range v2 {
				v3[i.(string)] = j
			}
			p.walkYamlMap(filepath, v3)
		}
	}
}
