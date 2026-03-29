package parser

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ynori7/credential-detector/config"
)

func Test_isParsableJavaScriptFile(t *testing.T) {
	testcases := map[string]struct {
		path     string
		expected bool
	}{
		"No extension": {
			path:     "/etc/passwd",
			expected: false,
		},
		"Not JS extension": {
			path:     "/home/blah/test.java",
			expected: false,
		},
		"JS extension": {
			path:     "/home/blah/app.js",
			expected: true,
		},
		"MJS extension": {
			path:     "/home/blah/module.mjs",
			expected: true,
		},
		"CJS extension": {
			path:     "/home/blah/common.cjs",
			expected: true,
		},
	}

	conf, err := config.ParseConfig(getTestConfig())
	require.NoError(t, err)
	parser := NewParser(conf)

	for testcase, testdata := range testcases {
		actual := parser.isParsableJavaScriptFile(testdata.path)

		assert.Equal(t, testdata.expected, actual, testcase)
	}
}

func TestParser_JavaScript(t *testing.T) {
	// given
	conf, err := config.ParseConfig(getTestConfig())
	require.NoError(t, err)
	file := "../testdata/dummy.js"

	// when
	parser := NewParser(conf)
	parseFileForTest(parser, file)

	// then
	res := parser.Results
	assert.Equal(t, 12, len(res))

	// Separate JS-parsed results from JSON-walked results
	jsResults := make([]Result, 0)
	jsonResults := make([]Result, 0)
	for _, r := range res {
		if r.Type == TypeJSONVariable || r.Type == TypeJSONListVal {
			jsonResults = append(jsonResults, r)
		} else {
			jsResults = append(jsResults, r)
		}
	}

	// 8 results from JS line-by-line parsing
	assert.Equal(t, 8, len(jsResults))

	jsByName := make(map[string]Result)
	for _, r := range jsResults {
		if r.Name != "" {
			jsByName[r.Name] = r
		}
	}

	// Variable declarations
	assert.Equal(t, TypeJSVariable, jsByName["password"].Type)
	assert.Equal(t, `"supersecure123!@#$"`, jsByName["password"].Value)
	assert.Equal(t, 4, jsByName["password"].Line)

	assert.Equal(t, TypeJSVariable, jsByName["apiKey"].Type)
	assert.Equal(t, `"sk-1234567890abcdef1234"`, jsByName["apiKey"].Value)

	assert.Equal(t, TypeJSVariable, jsByName["dbUri"].Type)

	// Module exports
	assert.Equal(t, TypeJSVariable, jsByName["API_KEY"].Type)
	assert.Equal(t, `"abcdef1234567890xyzzy"`, jsByName["API_KEY"].Value)

	// Exports assignment
	assert.Equal(t, TypeJSVariable, jsByName["salt"].Type)

	// Export const
	assert.Equal(t, TypeJSVariable, jsByName["accessKey"].Type)
	assert.Equal(t, `"AKIAIOSFODNN7EXAMPLE"`, jsByName["accessKey"].Value)

	// Comments with credentials
	commentResults := make([]Result, 0)
	for _, r := range jsResults {
		if r.Type == TypeJSComment {
			commentResults = append(commentResults, r)
		}
	}
	assert.Equal(t, 2, len(commentResults))

	// 3 results from JSON object parsing
	assert.Equal(t, 4, len(jsonResults))

	jsonByName := make(map[string]Result)
	for _, r := range jsonResults {
		jsonByName[r.Name] = r
	}
	assert.Equal(t, "myappvalue12345678", jsonByName["secret"].Value)
	assert.Equal(t, "nestedDbP@ss9876", jsonByName["password"].Value)
	assert.Equal(t, "nested-tok-abc1234", jsonByName["token"].Value)
	assert.Equal(t, "supersecret", jsonByName["DefaultPw"].Value)
}

func TestParser_JavaScriptMinified(t *testing.T) {
	// given
	conf, err := config.ParseConfig(getTestConfig())
	require.NoError(t, err)
	file := "../testdata/dummy_minified.js"

	// when
	parser := NewParser(conf)
	parseFileForTest(parser, file)

	// then
	res := parser.Results

	// Verify that credentials are still detected in minified code
	assert.True(t, len(res) > 0, "should find credentials in minified JS")

	// Check that specific credential variables were found
	foundNames := make(map[string]bool)
	for _, r := range res {
		if r.Name != "" {
			foundNames[r.Name] = true
		}
	}
	assert.True(t, foundNames["password"], "should find password")
	assert.True(t, foundNames["apiKey"], "should find apiKey")
	assert.True(t, foundNames["secret"], "should find secret")
	assert.True(t, foundNames["API_KEY"], "should find API_KEY")
}

func Test_isMinifiedJS(t *testing.T) {
	short := []byte("const x = 1;\nconst y = 2;\n")
	assert.False(t, isMinifiedJS(short))

	long := make([]byte, 600)
	for i := range long {
		long[i] = 'a'
	}
	assert.True(t, isMinifiedJS(long))
}

func Test_unminifyJS(t *testing.T) {
	minified := []byte(`var a="hello";var b="world";function foo(){return true;}`)
	result := unminifyJS(minified)

	// Should have newlines after semicolons and closing braces
	assert.Contains(t, result, ";\n")
	assert.Contains(t, result, "}\n")
}

func Test_jsObjectToJSON(t *testing.T) {
	block := "{\n    secret: \"myappvalue12345678\",\n    name: \"myapp\",\n    port: 8080,\n}"
	result := jsObjectToJSON(block)
	t.Log("Result:", result)

	var m map[string]interface{}
	err := json.Unmarshal([]byte(result), &m)
	assert.NoError(t, err, "should parse as valid JSON")
	if err == nil {
		assert.Equal(t, "myappvalue12345678", m["secret"])
		assert.Equal(t, "myapp", m["name"])
	}

	// With single-line comments
	blockWithComment := "{\n    // database credentials\n    secret: \"myappvalue12345678\",\n    name: \"myapp\",\n}"
	result2 := jsObjectToJSON(blockWithComment)
	err = json.Unmarshal([]byte(result2), &m)
	assert.NoError(t, err, "should parse as valid JSON after stripping single-line comments")
	if err == nil {
		assert.Equal(t, "myappvalue12345678", m["secret"])
	}

	// With multiline comments
	blockWithMultiline := "{\n    /* config */\n    secret: \"myappvalue12345678\",\n    name: \"myapp\",\n}"
	result3 := jsObjectToJSON(blockWithMultiline)
	err = json.Unmarshal([]byte(result3), &m)
	assert.NoError(t, err, "should parse as valid JSON after stripping multiline comments")
	if err == nil {
		assert.Equal(t, "myappvalue12345678", m["secret"])
	}
}
