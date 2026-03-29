package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ynori7/credential-detector/parser"
)

// --- Model tests ---

func TestScanSession_Dismiss(t *testing.T) {
	sess := &ScanSession{
		Results:   make([]parser.Result, 3),
		dismissed: make(map[int]bool),
	}

	assert.False(t, sess.IsDismissed(0))
	sess.Dismiss(0)
	assert.True(t, sess.IsDismissed(0))
	assert.False(t, sess.IsDismissed(1))
}

func TestScanSession_Dismiss_NilMap(t *testing.T) {
	sess := &ScanSession{
		Results: make([]parser.Result, 3),
	}

	// Dismiss should initialize the map
	sess.Dismiss(1)
	assert.True(t, sess.IsDismissed(1))
}

func TestScanSession_ActiveResults(t *testing.T) {
	sess := &ScanSession{
		Results: []parser.Result{
			{File: "a.go", Name: "key1"},
			{File: "b.go", Name: "key2"},
			{File: "c.go", Name: "key3"},
		},
		dismissed: make(map[int]bool),
	}

	active := sess.ActiveResults()
	assert.Len(t, active, 3)
	assert.Equal(t, 0, active[0].Index)
	assert.Equal(t, "key1", active[0].Result.Name)

	sess.Dismiss(1)
	active = sess.ActiveResults()
	assert.Len(t, active, 2)
	assert.Equal(t, 0, active[0].Index)
	assert.Equal(t, 2, active[1].Index)
}

// --- SessionStore tests ---

func TestSessionStore_CreateAndGet(t *testing.T) {
	store := &SessionStore{sessions: make(map[string]*ScanSession)}
	req := ScanRequest{Mode: ScanModeRepo, Target: "https://github.com/test/repo", Depth: ScanDepthHead}

	sess := store.Create(req)
	assert.NotEmpty(t, sess.ID)
	assert.Equal(t, ScanStatusRunning, sess.Status)
	assert.Equal(t, req.Target, sess.Request.Target)

	got, ok := store.Get(sess.ID)
	assert.True(t, ok)
	assert.Equal(t, sess, got)
}

func TestSessionStore_Get_NotFound(t *testing.T) {
	store := &SessionStore{sessions: make(map[string]*ScanSession)}
	_, ok := store.Get("nonexistent")
	assert.False(t, ok)
}

func TestSessionStore_Delete(t *testing.T) {
	store := &SessionStore{sessions: make(map[string]*ScanSession)}
	sess := store.Create(ScanRequest{Mode: ScanModeLocal, Target: "/tmp"})

	store.Delete(sess.ID)
	_, ok := store.Get(sess.ID)
	assert.False(t, ok)
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
	results := []IndexedResult{
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

// --- Scanner helper tests ---

func TestValidateRepoURL(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		expectErr bool
	}{
		{"github https", "https://github.com/owner/repo", false},
		{"gitlab https", "https://gitlab.com/owner/repo", false},
		{"bitbucket https", "https://bitbucket.org/owner/repo", false},
		{"github ssh", "ssh://github.com/owner/repo", false},
		{"github shorthand", "owner/repo", false},
		{"unsupported host", "https://evil.com/owner/repo", true},
		{"http scheme", "http://github.com/owner/repo", true},
		{"file scheme", "file:///etc/passwd", true},
		{"ftp scheme", "ftp://github.com/repo", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRepoURL(tc.url)
			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestIsGitHubURL(t *testing.T) {
	assert.True(t, isGitHubURL("https://github.com/owner/repo"))
	assert.True(t, isGitHubURL("owner/repo")) // shorthand
	assert.False(t, isGitHubURL("https://gitlab.com/owner/repo"))
	assert.False(t, isGitHubURL("git@gitlab.com:owner/repo.git"))
}

func TestRepoNameFromURL(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://github.com/owner/repo.git", "repo"},
		{"https://github.com/owner/repo", "repo"},
		{"repo", "repo"},
	}

	for _, tc := range tests {
		assert.Equal(t, tc.want, repoNameFromURL(tc.url), "url: %s", tc.url)
	}
}

func TestSortResults(t *testing.T) {
	results := []parser.Result{
		{File: "b.go", Line: 10, Name: "z"},
		{File: "a.go", Line: 5, Name: "x"},
		{File: "a.go", Line: 5, Name: "a"},
		{File: "a.go", Line: 1, Name: "y"},
	}

	sortResults(results)

	assert.Equal(t, "a.go", results[0].File)
	assert.Equal(t, 1, results[0].Line)
	assert.Equal(t, "a", results[1].Name)
	assert.Equal(t, "x", results[2].Name)
	assert.Equal(t, "b.go", results[3].File)
}

// --- Handler tests ---

func newTestServer(t *testing.T) *Server {
	t.Helper()
	scanner := NewScanner("", "")
	return NewServer(scanner)
}

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

	sess := srv.sessions.Create(ScanRequest{Mode: ScanModeRepo, Target: "test/repo"})
	sess.mu.Lock()
	sess.Status = ScanStatusComplete
	sess.Results = []parser.Result{
		{File: "a.go", Line: 1, Name: "password", Value: "secret123456"},
	}
	sess.Stats = parser.Statistics{FilesFound: 5, FilesScanned: 3, ResultsFound: 1}
	sess.mu.Unlock()

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

	sess := srv.sessions.Create(ScanRequest{Mode: ScanModeLocal, Target: "/tmp"})
	sess.mu.Lock()
	sess.Results = []parser.Result{{File: "a.go", Name: "key"}}
	sess.mu.Unlock()

	req := httptest.NewRequest(http.MethodDelete, "/scan/"+sess.ID+"/dismiss/abc", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleDismiss_OutOfRange(t *testing.T) {
	srv := newTestServer(t)

	sess := srv.sessions.Create(ScanRequest{Mode: ScanModeLocal, Target: "/tmp"})
	sess.mu.Lock()
	sess.Results = []parser.Result{{File: "a.go", Name: "key"}}
	sess.mu.Unlock()

	req := httptest.NewRequest(http.MethodDelete, "/scan/"+sess.ID+"/dismiss/5", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleDismiss_Success(t *testing.T) {
	srv := newTestServer(t)

	sess := srv.sessions.Create(ScanRequest{Mode: ScanModeLocal, Target: "/tmp"})
	sess.mu.Lock()
	sess.Results = []parser.Result{
		{File: "a.go", Name: "key1"},
		{File: "b.go", Name: "key2"},
	}
	sess.mu.Unlock()

	req := httptest.NewRequest(http.MethodDelete, "/scan/"+sess.ID+"/dismiss/0", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, sess.IsDismissed(0))
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

// --- Scanner failSession test ---

func TestFailSession(t *testing.T) {
	sc := &Scanner{}
	sess := &ScanSession{
		ID:        "test",
		Status:    ScanStatusRunning,
		Progress:  make(chan string, 64),
		dismissed: make(map[int]bool),
	}

	sc.failSession(sess, "something went wrong")

	assert.Equal(t, ScanStatusFailed, sess.Status)
	assert.Equal(t, "something went wrong", sess.Error)

	msg := <-sess.Progress
	assert.Contains(t, msg, "something went wrong")
}

// --- Scanner stripFilePrefix test ---

func TestStripFilePrefix(t *testing.T) {
	sc := &Scanner{}
	sess := &ScanSession{
		Results: []parser.Result{
			{File: "/tmp/credential-detector-123/repo/src/main.go"},
			{File: "/tmp/credential-detector-123/repo/config.yaml"},
		},
		dismissed: make(map[int]bool),
	}

	sc.stripFilePrefix(sess, "/tmp/credential-detector-123/repo")

	assert.Equal(t, "src/main.go", sess.Results[0].File)
	assert.Equal(t, "config.yaml", sess.Results[1].File)
}

// --- OrgName validation test ---

func TestOrgNameRegex(t *testing.T) {
	assert.True(t, orgNameRegex.MatchString("my-org"))
	assert.True(t, orgNameRegex.MatchString("my_org.name"))
	assert.True(t, orgNameRegex.MatchString("org123"))
	assert.False(t, orgNameRegex.MatchString("my org"))
	assert.False(t, orgNameRegex.MatchString("org/name"))
	assert.False(t, orgNameRegex.MatchString(""))
}

// --- Integration tests: actual scans ---

func testdataDir() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "testdata")
}

func drainProgress(sess *ScanSession) {
	for range sess.Progress {
	}
}

func TestRunLocalScan_Directory(t *testing.T) {
	// The default config excludes test directories (including "testdata"),
	// so scan the project root which contains non-test source files.
	projectRoot := filepath.Join(testdataDir(), "..")
	sc := NewScanner("", "")
	sess := &ScanSession{
		ID:        "test-local-dir",
		Request:   ScanRequest{Mode: ScanModeLocal, Target: projectRoot},
		Status:    ScanStatusRunning,
		Progress:  make(chan string, 256),
		dismissed: make(map[int]bool),
	}

	sc.RunLocalScan(context.Background(), sess)

	assert.Equal(t, ScanStatusComplete, sess.Status)
	assert.Empty(t, sess.Error)
	assert.Greater(t, sess.Stats.FilesFound, 0)
	assert.Greater(t, sess.Stats.FilesScanned, 0)
}

func TestRunLocalScan_SingleFile(t *testing.T) {
	sc := NewScanner("", "")
	target := filepath.Join(testdataDir(), "dummy.go")
	sess := &ScanSession{
		ID:        "test-local-file",
		Request:   ScanRequest{Mode: ScanModeLocal, Target: target},
		Status:    ScanStatusRunning,
		Progress:  make(chan string, 256),
		dismissed: make(map[int]bool),
	}

	sc.RunLocalScan(context.Background(), sess)

	assert.Equal(t, ScanStatusComplete, sess.Status)
	assert.Empty(t, sess.Error)
	assert.Greater(t, len(sess.Results), 0)

	// dummy.go should have known credentials like internalSecret, authToken, etc.
	var names []string
	for _, r := range sess.Results {
		names = append(names, r.Name)
	}
	assert.Contains(t, names, "internalSecret")
	assert.Contains(t, names, "authToken")
}

func TestRunLocalScan_YAMLFile(t *testing.T) {
	sc := NewScanner("", "")
	target := filepath.Join(testdataDir(), "dummy.yaml")
	sess := &ScanSession{
		ID:        "test-local-yaml",
		Request:   ScanRequest{Mode: ScanModeLocal, Target: target},
		Status:    ScanStatusRunning,
		Progress:  make(chan string, 256),
		dismissed: make(map[int]bool),
	}

	sc.RunLocalScan(context.Background(), sess)

	assert.Equal(t, ScanStatusComplete, sess.Status)
	assert.Greater(t, len(sess.Results), 0)

	var names []string
	for _, r := range sess.Results {
		names = append(names, r.Name)
	}
	assert.Contains(t, names, "accessKey")
}

func TestRunLocalScan_InvalidPath(t *testing.T) {
	sc := NewScanner("", "")
	sess := &ScanSession{
		ID:        "test-local-bad",
		Request:   ScanRequest{Mode: ScanModeLocal, Target: "/nonexistent/path/to/nowhere"},
		Status:    ScanStatusRunning,
		Progress:  make(chan string, 256),
		dismissed: make(map[int]bool),
	}

	sc.RunLocalScan(context.Background(), sess)

	assert.Equal(t, ScanStatusFailed, sess.Status)
	assert.NotEmpty(t, sess.Error)
}

func TestRunRepoScan_InvalidURL(t *testing.T) {
	sc := NewScanner("", "")
	sess := &ScanSession{
		ID:        "test-repo-bad",
		Request:   ScanRequest{Mode: ScanModeRepo, Target: "ftp://evil.com/repo"},
		Status:    ScanStatusRunning,
		Progress:  make(chan string, 256),
		dismissed: make(map[int]bool),
	}

	sc.RunRepoScan(context.Background(), sess)

	assert.Equal(t, ScanStatusFailed, sess.Status)
	assert.Contains(t, sess.Error, "Invalid URL")
}

func TestRunOrgScan_InvalidOrgName(t *testing.T) {
	sc := NewScanner("", "")
	sess := &ScanSession{
		ID:        "test-org-bad",
		Request:   ScanRequest{Mode: ScanModeOrg, Target: "invalid org name!"},
		Status:    ScanStatusRunning,
		Progress:  make(chan string, 256),
		dismissed: make(map[int]bool),
	}

	sc.RunOrgScan(context.Background(), sess)

	assert.Equal(t, ScanStatusFailed, sess.Status)
	assert.Contains(t, sess.Error, "Invalid organization name")
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
