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
	xmlText            = "#text"

	xmlNameAttr = "name"
)

var (
	//These are attributes which might identify the real purpose of an element like: <property key="password">blah</property>
	xmlElementAttributeIdentifierNames = map[string]struct{}{
		"id":   {},
		"key":  {},
		"name": {},
	}
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
	textBody := ""
	for k, v := range m {
		if reflect.TypeOf(v) == nil {
			continue
		}
		switch reflect.TypeOf(v).Kind() {
		case reflect.String:
			if k == xmlText {
				textBody = v.(string)
			}

			if strings.HasPrefix(k, xmlAttributePrefix) {
				siblings[strings.TrimPrefix(k, xmlAttributePrefix)] = v.(string)
			} else if strings.HasPrefix(k, xmlElementPrefix) && p.isPossiblyCredentialsVariable(parentKey, v.(string)) {
				p.resultChan <- Result{
					File:  filepath,
					Type:  TypeXMLElement,
					Name:  parentKey,
					Value: v.(string),
				}
			} else if p.isPossiblyCredentialsVariable(k, v.(string)) {
				p.resultChan <- Result{
					File:  filepath,
					Type:  TypeXMLElement,
					Name:  k,
					Value: v.(string),
				}
			}
		case reflect.Slice:
			p.parseXMLSlice(filepath, k, v)
		case reflect.Map:
			if v2, ok := v.(map[string]interface{}); ok {
				p.walkXMLMap(filepath, v2, k)
			}
		}
	}
	if textBody != "" && p.xmlAttributesContainCredentialsWithTextBody(textBody, siblings) {
		p.resultChan <- Result{
			File:  filepath,
			Type:  TypeXMLAttribute,
			Name:  parentKey,
			Value: p.buildXMLElementLine(parentKey, siblings, textBody),
		}
	}
	if p.xmlAttributesContainCredentials(siblings) {
		p.resultChan <- Result{
			File:  filepath,
			Type:  TypeXMLAttribute,
			Name:  parentKey,
			Value: p.buildXMLAttributeLine(parentKey, siblings),
		}
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
		//ignore all attributes in the xml attribute exclusion list
		if p.config.XMLAttributeNameExclusionPattern != "" && (p.xmlAttributeNameExclusionMatcher.MatchString(k) || p.xmlAttributeNameExclusionMatcher.MatchString(v)) {
			return false
		}

		if p.isPossiblyCredentialsVariable(k, v) {
			return true
		}
	}

	// if the key name wasn't suspicious then it doesn't make sense to check the values anymore when there's only one
	if len(siblings) < 2 {
		return false
	}

	if name, ok := siblings[xmlNameAttr]; ok {
		// check if this name plus one of the other values might be a a credential
		for _, v := range siblings {
			if v == name {
				continue //don't compare to itself
			}
			if p.isPossiblyCredentialsVariable(name, v) {
				return true
			}
		}

		return false //don't continue. if one of the attributes was "name", we can assume this is the variable name
	}

	//check if any of the value=>other value might be a credential pair, but check exclusions first
	countLongEnoughVals := 0
	for _, v := range siblings {
		if len(v) < p.config.MinPasswordLength {
			continue
		}
		countLongEnoughVals++

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

	if countLongEnoughVals < 2 {
		return false //there should be at least two values which are long enough
	}

	//now check inclusions
	for _, v := range siblings {
		for _, m := range p.variableNameMatchers {
			// include variables which have potentially suspicious names
			if m.MatchString(v) && !(p.config.VariableNameExclusionPattern != "" && p.variableNameExclusionMatcher.MatchString(v)) {
				return true
			}
		}
	}

	return false
}

func (p *Parser) xmlAttributesContainCredentialsWithTextBody(body string, siblings map[string]string) bool {
	for k, v := range siblings {
		//ignore all attributes which aren't likely to be identifiers
		if _, ok := xmlElementAttributeIdentifierNames[k]; !ok {
			continue
		}

		if p.isPossiblyCredentialsVariable(v, body) {
			return true
		}
	}
	return false
}

func (p *Parser) buildXMLAttributeLine(parent string, siblings map[string]string) string {
	attributes := make([]string, 0, len(siblings))
	for k, v := range siblings {
		attributes = append(attributes, fmt.Sprintf(" %s=\"%s\"", k, v))
	}
	sort.Strings(attributes)

	return fmt.Sprintf("<%s%s>", parent, strings.Join(attributes, ""))
}

func (p *Parser) buildXMLElementLine(parent string, siblings map[string]string, body string) string {
	attrLine := p.buildXMLAttributeLine(parent, siblings)
	return fmt.Sprintf("%s%s</%s>", attrLine, body, parent)
}
