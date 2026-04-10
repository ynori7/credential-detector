package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ynori7/credential-detector/config"
)

func Test_isParsableTypeScriptFile(t *testing.T) {
	testcases := map[string]struct {
		path     string
		expected bool
	}{
		"No extension": {
			path:     "/etc/passwd",
			expected: false,
		},
		"Not TS extension": {
			path:     "/home/blah/test.java",
			expected: false,
		},
		"JS extension (not TS)": {
			path:     "/home/blah/app.js",
			expected: false,
		},
		"TS extension": {
			path:     "/home/blah/app.ts",
			expected: true,
		},
		"TSX extension": {
			path:     "/home/blah/component.tsx",
			expected: true,
		},
	}

	conf, err := config.ParseConfig(getTestConfig())
	require.NoError(t, err)
	parser := NewParser(conf)

	for testcase, testdata := range testcases {
		actual := parser.isParsableTypeScriptFile(testdata.path)

		assert.Equal(t, testdata.expected, actual, testcase)
	}
}

func TestParser_TypeScript(t *testing.T) {
	// given
	conf, err := config.ParseConfig(getTestConfig())
	require.NoError(t, err)
	file := "../testdata/dummy.ts"

	// when
	parser := NewParser(conf)
	parseFileForTest(parser, file)

	// then
	res := parser.Results

	// Separate TS-parsed results from JSON-walked results
	tsResults := make([]Result, 0)
	jsonResults := make([]Result, 0)
	for _, r := range res {
		if r.Type == TypeJSONVariable || r.Type == TypeJSONListVal {
			jsonResults = append(jsonResults, r)
		} else {
			tsResults = append(tsResults, r)
		}
	}

	// 11 results from TS line-by-line parsing (9 variables + 2 comments)
	assert.Equal(t, 11, len(tsResults))

	tsByName := make(map[string]Result)
	for _, r := range tsResults {
		if r.Name != "" {
			tsByName[r.Name] = r
		}
	}

	// Variable declarations with type annotations
	assert.Equal(t, TypeTSVariable, tsByName["password"].Type)
	assert.Equal(t, `"supersecure123!@#$"`, tsByName["password"].Value)
	assert.Equal(t, 4, tsByName["password"].Line)

	assert.Equal(t, TypeTSVariable, tsByName["apiKey"].Type)
	assert.Equal(t, `"sk-1234567890abcdef1234"`, tsByName["apiKey"].Value)

	// Variable declaration without type annotation (Postgres URI value match)
	assert.Equal(t, TypeTSVariable, tsByName["dbUri"].Type)

	// Export const with type annotation
	assert.Equal(t, TypeTSVariable, tsByName["accessKey"].Type)
	assert.Equal(t, `"AKIAIOSFODNN7EXAMPLE"`, tsByName["accessKey"].Value)

	// Class properties with access modifiers
	assert.Equal(t, TypeTSVariable, tsByName["dbPassword"].Type)
	assert.Equal(t, `"dbP@ssw0rd9876"`, tsByName["dbPassword"].Value)

	assert.Equal(t, TypeTSVariable, tsByName["secret"].Type)
	assert.Equal(t, TypeTSVariable, tsByName["serviceApiKey"].Type)
	assert.Equal(t, TypeTSVariable, tsByName["token"].Type)
	assert.Equal(t, TypeTSVariable, tsByName["client_secret"].Type)
	assert.Equal(t, `'2452354e566456ryhfty656756756'`, tsByName["client_secret"].Value)

	tsVarResults := make([]Result, 0)
	for _, r := range tsResults {
		if r.Type == TypeTSVariable {
			tsVarResults = append(tsVarResults, r)
		}
	}
	// password, apiKey, dbUri, accessKey, dbPassword, secret, serviceApiKey, token, client_secret
	assert.Equal(t, 9, len(tsVarResults))

	// Comments with credentials
	commentResults := make([]Result, 0)
	for _, r := range tsResults {
		if r.Type == TypeTSComment {
			commentResults = append(commentResults, r)
		}
	}
	assert.Equal(t, 2, len(commentResults))

	// 4 results from JSON object parsing (secret, password, token, DefaultPw)
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
