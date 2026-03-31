package parser

import (
	"io/ioutil"
	"log"
	"reflect"
	"strings"

	"github.com/ynori7/credential-detector/config"
	"gopkg.in/yaml.v3"
)

// k8sArgKeys are the YAML list keys in which we look for CLI flag/value pairs
var k8sArgKeys = map[string]struct{}{
	"args":    {},
	"command": {},
}

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

	// K8s Secret: flag all data/stringData entries unconditionally
	if kind, ok := yamlData["kind"]; ok {
		if kindStr, ok := kind.(string); ok && strings.EqualFold(kindStr, "secret") {
			for _, dataKey := range []string{"data", "stringData"} {
				if raw, ok := yamlData[dataKey]; ok {
					if m, ok := raw.(map[string]interface{}); ok {
						for entryKey, entryVal := range m {
							valStr := ""
							if entryVal != nil {
								valStr = strings.TrimSpace(reflect.ValueOf(entryVal).String())
							}
							p.resultChan <- Result{
								File:           filepath,
								Type:           TypeK8sSecret,
								Name:           entryKey,
								Value:          valStr,
								CredentialType: "K8s Secret",
							}
						}
					}
					// Remove so walkYamlMap doesn't double-report Secret entries
					delete(yamlData, dataKey)
				}
			}
		}
	}

	p.walkYamlMap(filepath, yamlData)
}

func (p *Parser) walkYamlMap(filepath string, m map[string]interface{}) {
	// K8s env variable pattern: a map with both "name" and "value" string keys
	// e.g. - name: API_KEY
	//        value: "someSecret"
	if nameRaw, hasName := m["name"]; hasName {
		if valueRaw, hasValue := m["value"]; hasValue {
			if nameStr, ok := nameRaw.(string); ok {
				if valueStr, ok := valueRaw.(string); ok {
					if p.isPossiblyCredentialsVariable(nameStr, valueStr) {
						p.resultChan <- Result{
							File:  filepath,
							Type:  TypeK8sEnvVariable,
							Name:  nameStr,
							Value: valueStr,
						}
					}
				}
			}
		}
	}

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
	_, isArgList := k8sArgKeys[strings.ToLower(k)]

	s := reflect.ValueOf(v)
	for i := 0; i < s.Len(); i++ {
		switch v2 := s.Index(i).Interface().(type) {
		case string:
			// K8s CLI flag detection: in args/command lists, look for --flag followed by a value
			if isArgList && i+1 < s.Len() && isCliFlag(v2) {
				if nextStr, ok := s.Index(i + 1).Interface().(string); ok && !isCliFlag(nextStr) {
					flagName := normalizeCliFlag(v2)
					if p.isPossiblyCredentialsVariable(flagName, nextStr) {
						p.resultChan <- Result{
							File:  filepath,
							Type:  TypeK8sFlag,
							Name:  v2,
							Value: nextStr,
						}
					}
				}
			}
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

// isCliFlag reports whether s looks like a CLI flag (e.g. --foo or -f).
func isCliFlag(s string) bool {
	return strings.HasPrefix(s, "-")
}

// normalizeCliFlag strips leading dashes and replaces hyphens with underscores so
// "--api-key" becomes "api_key", making it easier to match against variableNamePatterns.
func normalizeCliFlag(flag string) string {
	stripped := strings.TrimLeft(flag, "-")
	return strings.ReplaceAll(stripped, "-", "_")
}
