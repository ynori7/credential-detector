package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ynori7/credential-detector/config"
	"github.com/ynori7/credential-detector/parser"
	"github.com/ynori7/credential-detector/web/model"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	scanner := NewScanner("", "")
	return NewServer(scanner)
}

// --- Template helper tests ---

func TestResultTypeName(t *testing.T) {
	tests := []struct {
		typ  int
		want string
	}{
		{parser.TypeGoComment, "Go Comment"},
		{parser.TypeGoVariable, "Go Variable"},
		{parser.TypeGoOther, "Go Other"},
		{parser.TypeJSONVariable, "JSON Variable"},
		{parser.TypeJSONListVal, "JSON List"},
		{parser.TypeYamlVariable, "YAML Variable"},
		{parser.TypeYamlListVal, "YAML List"},
		{parser.TypeK8sEnvVariable, "K8s Env Variable"},
		{parser.TypeK8sSecret, "K8s Secret"},
		{parser.TypeK8sFlag, "K8s CLI Flag"},
		{parser.TypePropertiesComment, "Properties Comment"},
		{parser.TypePropertiesValue, "Properties Value"},
		{parser.TypePrivateKey, "Private Key"},
		{parser.TypeXMLElement, "XML Element"},
		{parser.TypeXMLAttribute, "XML Attribute"},
		{parser.TypePHPVariable, "PHP Variable"},
		{parser.TypePHPHeredoc, "PHP Heredoc"},
		{parser.TypePHPConstant, "PHP Constant"},
		{parser.TypePHPComment, "PHP Comment"},
		{parser.TypePHPOther, "PHP Other"},
		{parser.TypeBashVariable, "Bash Variable"},
		{parser.TypeGenericCodeVariable, "Code Variable"},
		{parser.TypeGenericCodeComment, "Code Comment"},
		{parser.TypeGenericCodeOther, "Code Other"},
		{parser.TypeGeneric, "Generic"},
		{parser.TypeJSVariable, "JS Variable"},
		{parser.TypeJSComment, "JS Comment"},
		{parser.TypeJSOther, "JS Other"},
		{parser.TypeHTMLScript, "HTML Script"},
		{9999, "Unknown"},
	}

	for _, tc := range tests {
		assert.Equal(t, tc.want, resultTypeName(tc.typ), "type %d", tc.typ)
	}
}

func TestMaskValue(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"short", "*****"},
		{"12345678", "********"},
		{"abcdefghij", "abcd**ghij"},
		{"mysupersecretpassword", "mysu*************word"},
		{"", ""},
	}

	for _, tc := range tests {
		assert.Equal(t, tc.want, maskValue(tc.input), "input: %q", tc.input)
	}
}

func TestGroupByFile(t *testing.T) {
	results := []model.IndexedResult{
		{Index: 0, Result: parser.Result{File: "a.go", Name: "k1"}},
		{Index: 1, Result: parser.Result{File: "a.go", Name: "k2"}},
		{Index: 2, Result: parser.Result{File: "b.go", Name: "k3"}},
	}

	groups := groupByFile(results)
	require.Len(t, groups, 2)
	assert.Equal(t, "a.go", groups[0].File)
	assert.Len(t, groups[0].Results, 2)
	assert.Equal(t, "b.go", groups[1].File)
	assert.Len(t, groups[1].Results, 1)
}

func TestGroupByFile_Empty(t *testing.T) {
	groups := groupByFile(nil)
	assert.Empty(t, groups)
}

// --- splitLines tests ---

func TestSplitLines(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"", nil},
		{"  \n \n  ", nil},
		{"a\nb\nc", []string{"a", "b", "c"}},
		{"  a  \n  b  ", []string{"a", "b"}},
		{"a\n\nb", []string{"a", "b"}}, // blank lines skipped
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, splitLines(tc.input), "input: %q", tc.input)
	}
}

// --- validateConfig tests ---

func TestValidateConfig_Valid(t *testing.T) {
	c := &config.Config{
		ScanTypes:                    []string{config.ScanTypeGo, config.ScanTypeYaml},
		VariableNamePatterns:         []string{`(?i)secret`, `(?i)token`},
		VariableValueExcludePatterns: []string{`^test$`},
		FullTextValueExcludePatterns: []string{`postgres:\/\/.*@localhost`},
		ValueMatchPatterns: []config.ValueMatchPattern{
			{Name: "JWT", Pattern: `eyJ[a-zA-Z0-9_.]+`},
		},
		VariableNameExclusionPattern:     `(?i)format`,
		XMLAttributeNameExclusionPattern: `(?i)token`,
	}
	assert.NoError(t, validateConfig(c))
}

func TestValidateConfig_InvalidScanType(t *testing.T) {
	c := &config.Config{ScanTypes: []string{"notreal"}}
	err := validateConfig(c)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "notreal")
}

func TestValidateConfig_BadVariableNamePattern(t *testing.T) {
	c := &config.Config{VariableNamePatterns: []string{"[invalid"}}
	assert.Error(t, validateConfig(c))
}

func TestValidateConfig_BadValueMatchPattern(t *testing.T) {
	c := &config.Config{
		ValueMatchPatterns: []config.ValueMatchPattern{
			{Name: "bad", Pattern: "[invalid"},
		},
	}
	assert.Error(t, validateConfig(c))
}

func TestValidateConfig_BadVariableValueExcludePattern(t *testing.T) {
	c := &config.Config{VariableValueExcludePatterns: []string{"[invalid"}}
	assert.Error(t, validateConfig(c))
}

func TestValidateConfig_BadFullTextExcludePattern(t *testing.T) {
	c := &config.Config{FullTextValueExcludePatterns: []string{"[invalid"}}
	assert.Error(t, validateConfig(c))
}

func TestValidateConfig_BadExclusionPattern(t *testing.T) {
	c := &config.Config{VariableNameExclusionPattern: "[invalid"}
	assert.Error(t, validateConfig(c))
}

func TestValidateConfig_BadXMLExclusionPattern(t *testing.T) {
	c := &config.Config{XMLAttributeNameExclusionPattern: "[invalid"}
	assert.Error(t, validateConfig(c))
}

// --- parseConfigFromForm tests ---

func TestParseConfigFromForm_Basic(t *testing.T) {
	form := url.Values{
		"variableNamePatterns":         {"(?i)mySecret\n(?i)myToken"},
		"variableValueExcludePatterns": {"^dummy$"},
		"fullTextValueExcludePatterns": {"postgres://.*@localhost"},
		"testDirectories":              {"mocks\nfixtures"},
		"ignoreFiles":                  {"node_modules"},
		"genericFileExtensions":        {"env"},
		"genericCodeFileExtensions":    {"rs"},
		"variableNameExclusionPattern": {"(?i)format"},
		"minPasswordLength":            {"10"},
		"excludeTests":                 {"on"},
		"excludeComments":              {"on"},
		"verbose":                      {"on"},
		"scanTypes":                    {config.ScanTypeGo},
	}
	r := httptest.NewRequest(http.MethodPost, "/config", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	c, err := parseConfigFromForm(r)
	require.NoError(t, err)

	assert.Equal(t, []string{"(?i)mySecret", "(?i)myToken"}, c.VariableNamePatterns)
	assert.Equal(t, []string{"^dummy$"}, c.VariableValueExcludePatterns)
	assert.Equal(t, []string{"postgres://.*@localhost"}, c.FullTextValueExcludePatterns)
	assert.Equal(t, []string{"mocks", "fixtures"}, c.TestDirectories)
	assert.Equal(t, []string{"node_modules"}, c.IgnoreFiles)
	assert.Equal(t, []string{"env"}, c.GenericFileExtensions)
	assert.Equal(t, []string{"rs"}, c.GenericCodeFileExtensions)
	assert.Equal(t, "(?i)format", c.VariableNameExclusionPattern)
	assert.Equal(t, 10, c.MinPasswordLength)
	assert.True(t, c.ExcludeTests)
	assert.True(t, c.ExcludeComments)
	assert.True(t, c.Verbose)
	assert.Equal(t, []string{config.ScanTypeGo}, c.ScanTypes)
}

func TestParseConfigFromForm_CheckboxesOff(t *testing.T) {
	form := url.Values{} // no checkboxes submitted
	r := httptest.NewRequest(http.MethodPost, "/config", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	c, err := parseConfigFromForm(r)
	require.NoError(t, err)
	assert.False(t, c.ExcludeTests)
	assert.False(t, c.ExcludeComments)
	assert.False(t, c.Verbose)
}

func TestParseConfigFromForm_InvalidMinPasswordLength(t *testing.T) {
	form := url.Values{"minPasswordLength": {"notanumber"}}
	r := httptest.NewRequest(http.MethodPost, "/config", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err := parseConfigFromForm(r)
	assert.Error(t, err)
}

func TestParseConfigFromForm_NegativeMinPasswordLength(t *testing.T) {
	form := url.Values{"minPasswordLength": {"-1"}}
	r := httptest.NewRequest(http.MethodPost, "/config", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err := parseConfigFromForm(r)
	assert.Error(t, err)
}

func TestParseConfigFromForm_ValueMatchPatterns(t *testing.T) {
	form := url.Values{
		"vmpName[0]":    {"My Key"},
		"vmpPattern[0]": {"mykey_[A-Za-z0-9]+"},
		"vmpName[1]":    {"Another"},
		"vmpPattern[1]": {"another_[0-9]+"},
	}
	r := httptest.NewRequest(http.MethodPost, "/config", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	c, err := parseConfigFromForm(r)
	require.NoError(t, err)
	require.Len(t, c.ValueMatchPatterns, 2)

	names := []string{c.ValueMatchPatterns[0].Name, c.ValueMatchPatterns[1].Name}
	assert.Contains(t, names, "My Key")
	assert.Contains(t, names, "Another")
}

func TestParseConfigFromForm_ValueMatchPatterns_SkipsIncomplete(t *testing.T) {
	form := url.Values{
		"vmpName[0]":    {""},          // empty name → skip
		"vmpPattern[0]": {"mykey_[0]"}, // name empty → skip
		"vmpName[1]":    {"Good"},
		// no vmpPattern[1] → skip
	}
	r := httptest.NewRequest(http.MethodPost, "/config", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	c, err := parseConfigFromForm(r)
	require.NoError(t, err)
	assert.Empty(t, c.ValueMatchPatterns)
}

// --- Handler tests ---

func TestHandleIndex(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandleScan_InvalidMode(t *testing.T) {
	srv := newTestServer(t)

	form := url.Values{
		"mode":   {"invalid"},
		"target": {"https://github.com/owner/repo"},
	}

	req := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleScan_EmptyTarget(t *testing.T) {
	srv := newTestServer(t)

	form := url.Values{
		"mode":   {"repo"},
		"target": {""},
	}

	req := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleScan_LocalMode_RejectsURL(t *testing.T) {
	srv := newTestServer(t)

	form := url.Values{
		"mode":   {"local"},
		"target": {"https://github.com/owner/repo"},
	}

	req := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "local file path")
}

func TestHandleScan_LocalMode_RejectsRelativePath(t *testing.T) {
	srv := newTestServer(t)

	form := url.Values{
		"mode":   {"local"},
		"target": {"relative/path"},
	}

	req := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "absolute file path")
}

func TestHandleProgress_NotFound(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/scan/nonexistent/progress", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandleResults_NotFound(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/scan/nonexistent/results", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandleResults_WithSession(t *testing.T) {
	srv := newTestServer(t)

	sess := srv.sessions.Create(model.ScanRequest{Mode: model.ScanModeRepo, Target: "test/repo"})
	sess.Mu.Lock()
	sess.Status = model.ScanStatusComplete
	sess.Results = []parser.Result{
		{File: "a.go", Line: 1, Name: "password", Value: "secret123456"},
	}
	sess.Stats = parser.Statistics{FilesFound: 5, FilesScanned: 3, ResultsFound: 1}
	sess.Mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/scan/"+sess.ID+"/results", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "password")
}

func TestHandleDismiss_NotFound(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodDelete, "/scan/nonexistent/dismiss/0", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandleDismiss_InvalidIndex(t *testing.T) {
	srv := newTestServer(t)

	sess := srv.sessions.Create(model.ScanRequest{Mode: model.ScanModeLocal, Target: "/tmp"})
	sess.Mu.Lock()
	sess.Results = []parser.Result{{File: "a.go", Name: "key"}}
	sess.Mu.Unlock()

	req := httptest.NewRequest(http.MethodDelete, "/scan/"+sess.ID+"/dismiss/abc", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleDismiss_OutOfRange(t *testing.T) {
	srv := newTestServer(t)

	sess := srv.sessions.Create(model.ScanRequest{Mode: model.ScanModeLocal, Target: "/tmp"})
	sess.Mu.Lock()
	sess.Results = []parser.Result{{File: "a.go", Name: "key"}}
	sess.Mu.Unlock()

	req := httptest.NewRequest(http.MethodDelete, "/scan/"+sess.ID+"/dismiss/5", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleDismiss_Success(t *testing.T) {
	srv := newTestServer(t)

	sess := srv.sessions.Create(model.ScanRequest{Mode: model.ScanModeLocal, Target: "/tmp"})
	sess.Mu.Lock()
	sess.Results = []parser.Result{
		{File: "a.go", Name: "key1"},
		{File: "b.go", Name: "key2"},
	}
	sess.Mu.Unlock()

	req := httptest.NewRequest(http.MethodDelete, "/scan/"+sess.ID+"/dismiss/0", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, sess.IsDismissed(0))
}

func TestHandleDismissValue_NotFound(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodDelete, "/scan/nonexistent/dismiss-value?value=secret", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandleDismissValue_MissingValue(t *testing.T) {
	srv := newTestServer(t)

	sess := srv.sessions.Create(model.ScanRequest{Mode: model.ScanModeLocal, Target: "/tmp"})

	req := httptest.NewRequest(http.MethodDelete, "/scan/"+sess.ID+"/dismiss-value", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleDismissValue_Success(t *testing.T) {
	srv := newTestServer(t)

	sess := srv.sessions.Create(model.ScanRequest{Mode: model.ScanModeLocal, Target: "/tmp"})
	sess.Status = model.ScanStatusComplete
	sess.Mu.Lock()
	sess.Results = []parser.Result{
		{File: "a.go", Name: "key1", Value: "secret123"},
		{File: "b.go", Name: "key2", Value: "other"},
		{File: "c.go", Name: "key3", Value: "secret123"},
	}
	sess.Mu.Unlock()

	req := httptest.NewRequest(http.MethodDelete, "/scan/"+sess.ID+"/dismiss-value?value=secret123", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, sess.IsDismissed(0))
	assert.False(t, sess.IsDismissed(1))
	assert.True(t, sess.IsDismissed(2))
	// Response should be the re-rendered results partial
	assert.Contains(t, w.Body.String(), "other")
	assert.NotContains(t, w.Body.String(), "key1")
	assert.NotContains(t, w.Body.String(), "key3")
}

func TestHandleScan_ConcurrentLimit(t *testing.T) {
	srv := newTestServer(t)

	// Fill the semaphore to simulate an active scan
	srv.scanSem <- struct{}{}

	form := url.Values{
		"mode":   {"repo"},
		"target": {"https://github.com/owner/repo"},
	}

	req := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Contains(t, w.Body.String(), "already in progress")

	// Release semaphore
	<-srv.scanSem
}

func TestHandleScan_LocalMode_EndToEnd(t *testing.T) {
	srv := newTestServer(t)

	form := url.Values{
		"mode":   {"local"},
		"target": {testdataDir()},
	}

	req := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	// Should return 200 with the progress partial (scan started in background)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "sessionId")
}

// --- More buildEditorData tests ---

func TestBuildEditorData_Override_ZeroMinPasswordLength_KeepsDefault(t *testing.T) {
	defaults := &config.Config{MinPasswordLength: 6}
	override := &config.Config{MinPasswordLength: 0} // not set
	d := model.BuildEditorData(defaults, override)
	assert.Equal(t, 6, d.MinPasswordLength)
}

func TestBuildEditorData_Override_EmptyExclusionPattern_KeepsDefault(t *testing.T) {
	defaults := &config.Config{VariableNameExclusionPattern: "(?i)format"}
	override := &config.Config{VariableNameExclusionPattern: ""}
	d := model.BuildEditorData(defaults, override)
	assert.Equal(t, "(?i)format", d.VariableNameExclusionPattern)
}

// --- Config handler tests ---

func TestHandleConfigGet_NoOverride(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/config", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	// The editor template should be rendered
	assert.Contains(t, w.Body.String(), "config-editor")
}

func TestHandleConfigSave_Valid(t *testing.T) {
	srv := newTestServer(t)

	form := url.Values{
		"minPasswordLength": {"15"},
		"scanTypes":         {config.ScanTypeGo},
	}
	req := httptest.NewRequest(http.MethodPost, "/config", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Configuration applied")

	// Cookie should be set
	cookies := w.Result().Cookies()
	var configID string
	for _, c := range cookies {
		if c.Name == "config_id" {
			configID = c.Value
		}
	}
	require.NotEmpty(t, configID)

	// The stored config should have our values
	stored := srv.configStore.Get(configID)
	require.NotNil(t, stored)
	assert.Equal(t, 15, stored.MinPasswordLength)
	assert.Equal(t, []string{config.ScanTypeGo}, stored.ScanTypes)
}

func TestHandleConfigSave_InvalidRegex(t *testing.T) {
	srv := newTestServer(t)

	form := url.Values{
		"variableNamePatterns": {"[invalid regex"},
	}
	req := httptest.NewRequest(http.MethodPost, "/config", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Validation error")
}

func TestHandleConfigSave_InvalidScanType(t *testing.T) {
	srv := newTestServer(t)

	form := url.Values{
		"scanTypes": {"notavalidtype"},
	}
	req := httptest.NewRequest(http.MethodPost, "/config", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleConfigDelete_ClearsCookie(t *testing.T) {
	srv := newTestServer(t)

	// First save a config
	conf := &config.Config{MinPasswordLength: 99}
	id := srv.configStore.Save(conf)

	req := httptest.NewRequest(http.MethodDelete, "/config", nil)
	req.AddCookie(&http.Cookie{Name: "config_id", Value: id})
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Cookie should be expired / cleared
	var found bool
	for _, c := range w.Result().Cookies() {
		if c.Name == "config_id" {
			found = true
			assert.LessOrEqual(t, c.MaxAge, 0)
		}
	}
	assert.True(t, found, "expected config_id cookie to be cleared")

	// Config should be removed from store
	assert.Nil(t, srv.configStore.Get(id))
}

func TestHandleConfigExport_EmptyForm(t *testing.T) {
	srv := newTestServer(t)

	// Posting an empty form (no values changed)
	req := httptest.NewRequest(http.MethodPost, "/config/export", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Disposition"), "attachment")
	assert.Contains(t, w.Header().Get("Content-Disposition"), "credential-detector-config.yaml")
	assert.NotEmpty(t, w.Body.String())
}

func TestHandleConfigExport_WithFormValues(t *testing.T) {
	srv := newTestServer(t)

	form := url.Values{
		"minPasswordLength": {"20"},
		"scanTypes":         {config.ScanTypeGo},
		"excludeTests":      {"on"},
	}
	req := httptest.NewRequest(http.MethodPost, "/config/export", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "minPasswordLength: 20")
	assert.Contains(t, w.Body.String(), "go")
	assert.Contains(t, w.Body.String(), "excludeTests: true")
}

func TestHandleConfigExport_InvalidRegex(t *testing.T) {
	srv := newTestServer(t)

	form := url.Values{"variableNamePatterns": {"[invalid"}}
	req := httptest.NewRequest(http.MethodPost, "/config/export", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleScan_UsesConfigCookie(t *testing.T) {
	srv := newTestServer(t)

	// Save a config override
	override := &config.Config{MinPasswordLength: 50}
	id := srv.configStore.Save(override)

	form := url.Values{
		"mode":   {"local"},
		"target": {testdataDir()},
	}
	req := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "config_id", Value: id})
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// Find the created session and verify override is attached
	var found bool
	srv.sessions.Mu.RLock()
	for _, sess := range srv.sessions.Sessions {
		if sess.ConfigOverride != nil && sess.ConfigOverride.MinPasswordLength == 50 {
			found = true
		}
	}
	srv.sessions.Mu.RUnlock()
	assert.True(t, found, "expected at least one session with ConfigOverride.MinPasswordLength==50")
}

func TestHandleScan_NoConfigCookie_NilOverride(t *testing.T) {
	srv := newTestServer(t)

	form := url.Values{
		"mode":   {"local"},
		"target": {testdataDir()},
	}
	req := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// No override should be attached — all sessions should have nil ConfigOverride
	srv.sessions.Mu.RLock()
	for _, sess := range srv.sessions.Sessions {
		assert.Nil(t, sess.ConfigOverride)
	}
	srv.sessions.Mu.RUnlock()
}

func TestHandleIndex_WithConfigCookie(t *testing.T) {
	srv := newTestServer(t)

	override := &config.Config{MinPasswordLength: 42}
	id := srv.configStore.Save(override)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "config_id", Value: id})
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	// The "custom config active" badge should appear when HasOverride is true
	assert.Contains(t, w.Body.String(), "Custom config active")
}

func TestHandleIndex_WithInvalidConfigCookie(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "config_id", Value: "doesnotexist"})
	w := httptest.NewRecorder()

	// Should still render the page normally (unknown IDs return nil from the store)
	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// --- Repo filter tests ---

func TestHandleScan_OrgMode_RepoFilter(t *testing.T) {
	srv := newTestServer(t)

	form := url.Values{
		"mode":        {"org"},
		"target":      {"my-org"},
		"repo_filter": {"my-service-*"},
	}

	req := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	// Scan starts (returns progress partial) — verify the session has the filter
	require.Equal(t, http.StatusOK, w.Code)

	srv.sessions.Mu.RLock()
	defer srv.sessions.Mu.RUnlock()
	for _, sess := range srv.sessions.Sessions {
		assert.Equal(t, "my-service-*", sess.Request.OrgFilter.RepoPattern)
	}
}

// --- Pagination tests ---

func makeResults(n int) []parser.Result {
	results := make([]parser.Result, n)
	for i := 0; i < n; i++ {
		results[i] = parser.Result{
			File: fmt.Sprintf("file%d.go", i),
			Line: i + 1,
			Name: fmt.Sprintf("key%d", i),
		}
	}
	return results
}

func TestHandleResults_Pagination_FirstPage(t *testing.T) {
	srv := newTestServer(t)

	sess := srv.sessions.Create(model.ScanRequest{Mode: model.ScanModeRepo, Target: "test/repo"})
	sess.Mu.Lock()
	sess.Status = model.ScanStatusComplete
	sess.Results = makeResults(120)
	sess.Stats = parser.Statistics{ResultsFound: 120}
	sess.Mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/scan/"+sess.ID+"/results?page=1&page_size=50", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "key0")
	assert.Contains(t, body, "key49")
	assert.NotContains(t, body, "key50")
	assert.Contains(t, body, "Load More Results")
}

func TestHandleResults_Pagination_SecondPage(t *testing.T) {
	srv := newTestServer(t)

	sess := srv.sessions.Create(model.ScanRequest{Mode: model.ScanModeRepo, Target: "test/repo"})
	sess.Mu.Lock()
	sess.Status = model.ScanStatusComplete
	sess.Results = makeResults(120)
	sess.Stats = parser.Statistics{ResultsFound: 120}
	sess.Mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/scan/"+sess.ID+"/results?page=2&page_size=50", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "key50")
	assert.Contains(t, body, "key99")
	assert.NotContains(t, body, "key0")
	assert.Contains(t, body, "Load More Results")
}

func TestHandleResults_Pagination_LastPage(t *testing.T) {
	srv := newTestServer(t)

	sess := srv.sessions.Create(model.ScanRequest{Mode: model.ScanModeRepo, Target: "test/repo"})
	sess.Mu.Lock()
	sess.Status = model.ScanStatusComplete
	sess.Results = makeResults(120)
	sess.Stats = parser.Statistics{ResultsFound: 120}
	sess.Mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/scan/"+sess.ID+"/results?page=3&page_size=50", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "key100")
	assert.Contains(t, body, "key119")
	assert.NotContains(t, body, "Load More Results")
}

func TestHandleResults_Pagination_DefaultPageSize(t *testing.T) {
	srv := newTestServer(t)

	sess := srv.sessions.Create(model.ScanRequest{Mode: model.ScanModeRepo, Target: "test/repo"})
	sess.Mu.Lock()
	sess.Status = model.ScanStatusComplete
	sess.Results = makeResults(60)
	sess.Stats = parser.Statistics{ResultsFound: 60}
	sess.Mu.Unlock()

	// No page params — should default to page 1, page_size 50
	req := httptest.NewRequest(http.MethodGet, "/scan/"+sess.ID+"/results", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "key0")
	assert.Contains(t, body, "key49")
	assert.NotContains(t, body, "key50")
	assert.Contains(t, body, "Load More Results")
}

func TestHandleResults_Pagination_InvalidPage(t *testing.T) {
	srv := newTestServer(t)

	sess := srv.sessions.Create(model.ScanRequest{Mode: model.ScanModeRepo, Target: "test/repo"})
	sess.Mu.Lock()
	sess.Status = model.ScanStatusComplete
	sess.Results = makeResults(10)
	sess.Stats = parser.Statistics{ResultsFound: 10}
	sess.Mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/scan/"+sess.ID+"/results?page=-1", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "key0")
}

func TestHandleResults_Pagination_SmallResultSet(t *testing.T) {
	srv := newTestServer(t)

	sess := srv.sessions.Create(model.ScanRequest{Mode: model.ScanModeRepo, Target: "test/repo"})
	sess.Mu.Lock()
	sess.Status = model.ScanStatusComplete
	sess.Results = makeResults(5)
	sess.Stats = parser.Statistics{ResultsFound: 5}
	sess.Mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/scan/"+sess.ID+"/results?page=1&page_size=50", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "key4")
	assert.NotContains(t, body, "Load More Results")
}

// --- Export results tests ---

func TestHandleExportResults_Success(t *testing.T) {
	srv := newTestServer(t)

	sess := srv.sessions.Create(model.ScanRequest{Mode: model.ScanModeRepo, Target: "test/repo"})
	sess.Mu.Lock()
	sess.Status = model.ScanStatusComplete
	sess.Results = []parser.Result{
		{File: "a.go", Line: 1, Name: "password", Value: "secret123"},
		{File: "b.go", Line: 5, Name: "token", Value: "tok456"},
	}
	sess.Stats = parser.Statistics{FilesFound: 10, FilesScanned: 8, ResultsFound: 2}
	sess.Dismissed[0] = true // dismiss "password"
	sess.Mu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/scan/"+sess.ID+"/export", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Header().Get("Content-Disposition"), "attachment")

	var exported model.ExportData
	err := json.Unmarshal(w.Body.Bytes(), &exported)
	require.NoError(t, err)
	assert.Equal(t, 1, exported.Version)
	// Dismissed result should be excluded; only "token" exported
	assert.Len(t, exported.Results, 1)
	assert.Equal(t, "token", exported.Results[0].Name)
	assert.Equal(t, 1, exported.Stats.ResultsFound)
	// No dismissed map in export since all exported results are active
	assert.Empty(t, exported.Dismissed)
}

func TestHandleExportResults_NotFound(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/scan/nonexistent/export", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Import results tests ---

func createMultipartRequest(t *testing.T, url string, data []byte) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, err := writer.CreateFormFile("results_file", "results.json")
	require.NoError(t, err)
	_, err = part.Write(data)
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	req := httptest.NewRequest(http.MethodPost, url, &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

func TestHandleImportResults_Success(t *testing.T) {
	srv := newTestServer(t)

	exportData := model.ExportData{
		Version: 1,
		Request: model.ScanRequest{Mode: model.ScanModeRepo, Target: "test/repo"},
		Results: []parser.Result{
			{File: "a.go", Line: 1, Name: "key1", Value: "val1"},
			{File: "b.go", Line: 2, Name: "key2", Value: "val2"},
		},
		Stats:     parser.Statistics{FilesFound: 5, FilesScanned: 3, ResultsFound: 2},
		Dismissed: map[int]bool{0: true},
	}
	data, err := json.Marshal(exportData)
	require.NoError(t, err)

	req := createMultipartRequest(t, "/import", data)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	// Dismissed result (key1) should not appear, key2 should
	assert.NotContains(t, body, "key1")
	assert.Contains(t, body, "key2")
}

func TestHandleImportResults_InvalidJSON(t *testing.T) {
	srv := newTestServer(t)

	req := createMultipartRequest(t, "/import", []byte("not json"))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid JSON")
}

func TestHandleImportResults_EmptyFile(t *testing.T) {
	srv := newTestServer(t)

	req := createMultipartRequest(t, "/import", []byte(""))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "empty")
}

func TestHandleImportResults_UnsupportedVersion(t *testing.T) {
	srv := newTestServer(t)

	data, _ := json.Marshal(model.ExportData{Version: 99})
	req := createMultipartRequest(t, "/import", data)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Unsupported export version")
}

func TestHandleImportResults_MissingFile(t *testing.T) {
	srv := newTestServer(t)

	// POST to /import without a file field
	req := httptest.NewRequest(http.MethodPost, "/import", strings.NewReader(""))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=----test")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}
