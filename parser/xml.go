package parser

import (
	"fmt"
	"io/ioutil"
	"log"
	"reflect"
	"sort"
	"strings"

	"github.com/clbanning/mxj/v2"
	"github.com/ynori7/credential-detector/config"
)

const (
	xmlSuffix = ".xml"
)

const (
	xmlAttributePrefix = "-"
	xmlElementPrefix   = "#"
)

func (p *Parser) isParsableXMLFile(filepath string) bool {
	_, extension := getFileNameAndExtension(filepath)

	_, ok := p.scanTypes[config.ScanTypeXML]

	return ok && extension == xmlSuffix
}

func (p *Parser) parseXMLFile(filepath string) {

	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		if p.config.Verbose {
			log.Printf("could not read %s: %v", filepath, err)
		}
		return
	}

	if len(data) == 0 {
		return
	}

	mv, err := mxj.NewMapXml([]byte(data))
	if err != nil {
		if p.config.Verbose {
			log.Printf("could not parse %s: %v", filepath, err)
		}
		return
	}

	p.walkXMLMap(filepath, mv, "")
}

func (p *Parser) walkXMLMap(filepath string, m map[string]interface{}, parentKey string) {
	siblings := make(map[string]string)
	for k, v := range m {
		if reflect.TypeOf(v) == nil {
			continue
		}
		switch reflect.TypeOf(v).Kind() {
		case reflect.String:
			if strings.HasPrefix(k, xmlAttributePrefix) {
				siblings[strings.TrimPrefix(k, xmlAttributePrefix)] = v.(string)
			} else if strings.HasPrefix(k, xmlElementPrefix) && p.isPossiblyCredentialsVariable(parentKey, v.(string)) {
				p.Results = append(p.Results, Result{
					File:  filepath,
					Type:  TypeXmlElement,
					Name:  parentKey,
					Value: v.(string),
				})
			} else if p.isPossiblyCredentialsVariable(k, v.(string)) {
				p.Results = append(p.Results, Result{
					File:  filepath,
					Type:  TypeXmlElement,
					Name:  k,
					Value: v.(string),
				})
			}
		case reflect.Slice:
			p.parseXMLSlice(filepath, k, v)
		case reflect.Map:
			if v2, ok := v.(map[string]interface{}); ok {
				p.walkXMLMap(filepath, v2, k)
			}
		}
	}
	if p.xmlAttributesContainCredentials(siblings) {
		p.Results = append(p.Results, Result{
			File:  filepath,
			Type:  TypeXmlAttribute,
			Name:  parentKey,
			Value: p.buildXmlAttributeLine(parentKey, siblings),
		})
	}
}

func (p *Parser) parseXMLSlice(filepath string, k string, v interface{}) {
	s := reflect.ValueOf(v)
	for i := 0; i < s.Len(); i++ {
		switch v2 := s.Index(i).Interface().(type) {
		case map[string]interface{}:
			p.walkXMLMap(filepath, v2, k)
		}
	}
}

func (p *Parser) xmlAttributesContainCredentials(siblings map[string]string) bool {
	//check if any of the sibling keys=>value might be a credential pair
	for k, v := range siblings {
		if p.isPossiblyCredentialsVariable(k, v) {
			return true
		}
	}

	// if the key name wasn't suspicious then it doesn't make sense to check the values anymore when there's only one
	if len(siblings) == 1 {
		return false
	}

	//check if any of the value=>other value might be a credential pair, but check exclusions first
	for _, v := range siblings {
		if v == "" {
			return false
		}

		// if exclusions are defined for variable names, check
		if p.config.VariableNameExclusionPattern != "" && p.variableNameExclusionMatcher.MatchString(v) {
			return false
		}

		// exclude any variables whose value is in our exclusion list (this would include things like defaults and test values)
		for _, m := range p.valueExcludeMatchers {
			if m.MatchString(v) {
				return false
			}
		}
	}

	//now check inclusions
	for _, v := range siblings {
		for _, m := range p.variableNameMatchers {
			// include variables which have potentially suspicious names
			if m.MatchString(v)  {
				return true
			}
		}
	}

	return false
}

func (p *Parser) buildXmlAttributeLine(parent string, siblings map[string]string) string {
	attributes := make([]string, 0, len(siblings))
	for k, v := range siblings {
		attributes = append(attributes, fmt.Sprintf(" %s=\"%s\"", k, v))
	}
	sort.Strings(attributes)

	return fmt.Sprintf("<%s%s>", parent, strings.Join(attributes, ""))
}