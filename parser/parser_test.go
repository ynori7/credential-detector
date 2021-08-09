package parser

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ynori7/credential-detector/config"
)

func TestParser_Go(t *testing.T) {
	// given
	conf, err := config.ParseConfig(getTestConfig())
	require.NoError(t, err)
	file := "../testdata/dummy.go"

	expected := []Result{
		{
			File:  file,
			Type:  TypeGoVariable,
			Line:  5,
			Name:  "internalSecret",
			Value: `"asdfasdfasdf"`,
		},
		{
			File:  file,
			Type:  TypeGoVariable,
			Line:  9,
			Name:  "authToken",
			Value: `"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"`,
		},
		{
			File:  file,
			Type:  TypeGoVariable,
			Line:  13,
			Name:  "AccessCode",
			Value: `"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"`,
		},
		{
			File:  file,
			Type:  TypeGoVariable,
			Line:  17,
			Name:  "RealPostgresUri",
			Value: `"postgres://myuser:password123@blah.com:5432/mydb?sslmode=disable"`,
		},
		{
			File:  file,
			Type:  TypeGoVariable,
			Line:  47,
			Name:  "blahToken",
			Value: `"password"`,
		},
		{
			File: file,
			Type: TypeGoComment,
			Line: 20,
			Name: "",
			Value: `/*
Multiline comment
postgres://myuser:password123@somepostgresdb:5432/mydb?sslmode=disable
*/`,
		},
		{
			File: file,
			Type: TypeGoComment,
			Line: 51,
			Name: "",
			Value: `// this is a local comment
// "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"`,
		},
	}

	// when
	parser := NewParser(conf)
	parser.ParseFile(file)

	// then
	res := parser.Results
	assert.Equal(t, len(expected), len(res))
	assert.Equal(t, expected, res)
}

func TestParser_Json(t *testing.T) {
	// given
	conf, err := config.ParseConfig(getTestConfig())
	require.NoError(t, err)
	file := "../testdata/dummy.json"
	expected := []Result{
		{
			File:  file,
			Type:  TypeJsonVariable,
			Line:  0,
			Name:  "apiKey",
			Value: `aslkdjflkjwe#Kjkjoi3`,
		},
		{
			File:  file,
			Type:  TypeJsonVariable,
			Line:  0,
			Name:  "secret",
			Value: `23423Ksk3s`,
		},
		{
			File:  file,
			Type:  TypeJsonVariable,
			Line:  0,
			Name:  "token",
			Value: `lkaskjlklejer#4`,
		},
		{
			File:  file,
			Type:  TypeJsonListVal,
			Line:  0,
			Name:  "stuff2",
			Value: `postgres://myuser:password123@somepostgresdb:5432/mydb?sslmode=disable`,
		},
	}

	// when
	parser := NewParser(conf)
	parser.ParseFile(file)

	// then
	res := parser.Results
	sort.Slice(res, func(i, j int) bool {
		return res[i].Name < res[j].Name
	})
	sort.Slice(expected, func(i, j int) bool {
		return expected[i].Name < expected[j].Name
	})

	assert.Equal(t, len(expected), len(res))
	assert.Equal(t, expected, res)
}

func TestParser_JsonList(t *testing.T) {
	// given
	conf, err := config.ParseConfig(getTestConfig())
	require.NoError(t, err)
	file := "../testdata/dummylist.json"
	expected := []Result{
		{
			File:  file,
			Type:  TypeJsonVariable,
			Line:  0,
			Name:  "Password",
			Value: `asdfawekrjwe`,
		},
	}

	// when
	parser := NewParser(conf)
	parser.ParseFile(file)

	// then
	res := parser.Results
	sort.Slice(res, func(i, j int) bool {
		return res[i].Name < res[j].Name
	})
	sort.Slice(expected, func(i, j int) bool {
		return expected[i].Name < expected[j].Name
	})

	assert.Equal(t, len(expected), len(res))
	assert.Equal(t, expected, res)
}

func TestParser_Yaml(t *testing.T) {
	// given
	conf, err := config.ParseConfig(getTestConfig())
	require.NoError(t, err)
	file := "../testdata/dummy.yaml"
	expected := []Result{
		{
			File:  file,
			Type:  TypeYamlVariable,
			Line:  0,
			Name:  "accessKey",
			Value: `2342342kjasdre`,
		},
		{
			File:  file,
			Type:  TypeYamlListVal,
			Line:  0,
			Name:  "args",
			Value: `postgres://myuser:password123@somepostgresdb:5432/mydb?sslmode=disable`,
		},
	}

	// when
	parser := NewParser(conf)
	parser.ParseFile(file)

	// then
	res := parser.Results
	sort.Slice(res, func(i, j int) bool {
		return res[i].Name < res[j].Name
	})
	sort.Slice(expected, func(i, j int) bool {
		return expected[i].Name < expected[j].Name
	})

	assert.Equal(t, len(expected), len(res))
	assert.Equal(t, expected, res)
}

func getTestConfig() []byte {
	return []byte(`variableNamePatterns:
  - (?i)passwd|password
  - (?i)secret
  - (?i)token
  - (?i)apiKey|api[_-]key
  - (?i)accessKey|access[_-]key
  - (?i)bearer
  - (?i)credentials
  - salt|SALT|Salt
variableNameExclusionPattern: (?i)format|tokenizer|secretName|Error$
valueMatchPatterns:
  - postgres:\/\/.+:.+@.+:.+\/.+ #postgres connection uri with password
  - eyJhbGciOiJIUzI1NiIsInR5cCI[a-zA-Z0-9_.]+ #jwt token
valueExcludePatterns:
  - postgres:\/\/.+:.+@localhost:.+\/.+ #default postgres uri for testing
  - postgres:\/\/.+:.+@127.0.0.1:.+\/.+ #default postgres uri for testing
  - postgres:\/\/postgres:postgres@postgres:.+\/.+ #default postgres uri for testing
  - (?i)^test$|^postgres$|^root$|^foobar$|^example$|^changeme$|^default$ #common dummy values
  - (?i)^true$|^false$
  - (?i)^bearer$
excludeTests: true
testDirectories:
  - test
  - testdata
excludeComments: false
scanTypes: #possible values are go|yaml|json
  - go
  - yaml
  - json
disableOutputColors: false
verbose: false`)
}
