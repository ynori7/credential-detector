package parser

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"reflect"
	"strings"
)

const (
	JsonSuffix     = ".json"
	LockFileSuffix = "lock.json"
)

func (p *Parser) isParsableJsonFile(filepath string) bool {
	return p.config.IncludeJsonFiles && strings.HasSuffix(filepath, JsonSuffix) && !strings.HasSuffix(filepath, LockFileSuffix)
}

func (p *Parser) ParseJsonFile(filepath string) {

	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		log.Printf("could not parse %s: %v", filepath, err)
		return
	}

	if len(data) == 0 {
		return
	}

	if string(data[0]) == "{" {
		jsonData := make(map[string]interface{})

		err = json.Unmarshal(data, &jsonData)
		if err != nil {
			if p.config.Verbose {
				log.Printf("unmarshal json from %s: %v", filepath, err)
			}
			return
		}

		p.walkJsonMap(filepath, jsonData)
	} else if string(data[0]) == "[" {
		jsonData := make([]interface{}, 0)

		err = json.Unmarshal(data, &jsonData)
		if err != nil {
			if p.config.Verbose {
				log.Printf("unmarshal json from %s: %v", filepath, err)
			}
			return
		}

		p.parseJsonSlice(filepath, "", jsonData)
	}
}

func (p *Parser) walkJsonMap(filepath string, m map[string]interface{}) {
	for k, v := range m {
		if reflect.TypeOf(v) == nil {
			continue
		}
		switch reflect.TypeOf(v).Kind() {
		case reflect.String:
			if p.isPossiblyCredentialsVariable(k, v.(string)) {
				p.Results = append(p.Results, Result{
					File:  filepath,
					Type:  TypeJsonVariable,
					Name:  k,
					Value: v.(string),
				})
			}
		case reflect.Slice:
			p.parseJsonSlice(filepath, k, v)
		case reflect.Map:
			if v2, ok := v.(map[string]interface{}); ok {
				p.walkJsonMap(filepath, v2)
			}
		}
	}
}

func (p *Parser) parseJsonSlice(filepath string, k string, v interface{}) {
	s := reflect.ValueOf(v)
	for i := 0; i < s.Len(); i++ {
		switch v2 := s.Index(i).Interface().(type) {
		case string:
			if p.isPossiblyCredentialValue(v2) {
				p.Results = append(p.Results, Result{
					File:  filepath,
					Type:  TypeJsonListVal,
					Name:  k,
					Value: v2,
				})
			}
		case map[string]interface{}:
			p.walkJsonMap(filepath, v2)
		}
	}
}
