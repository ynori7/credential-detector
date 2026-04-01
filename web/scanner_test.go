package web

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ynori7/credential-detector/config"
	"github.com/ynori7/credential-detector/parser"
	"github.com/ynori7/credential-detector/web/model"
)

func testdataDir() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "testdata")
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

func TestFailSession(t *testing.T) {
	sc := &Scanner{}
	sess := &model.ScanSession{
		ID:        "test",
		Status:    model.ScanStatusRunning,
		Progress:  make(chan string, 64),
		Dismissed: make(map[int]bool),
	}

	sc.failSession(sess, "something went wrong")

	assert.Equal(t, model.ScanStatusFailed, sess.Status)
	assert.Equal(t, "something went wrong", sess.Error)

	msg := <-sess.Progress
	assert.Contains(t, msg, "something went wrong")
}

func TestStripFilePrefix(t *testing.T) {
	sc := &Scanner{}
	sess := &model.ScanSession{
		Results: []parser.Result{
			{File: "/tmp/credential-detector-123/repo/src/main.go"},
			{File: "/tmp/credential-detector-123/repo/config.yaml"},
		},
		Dismissed: make(map[int]bool),
	}

	sc.stripFilePrefix(sess, "/tmp/credential-detector-123/repo")

	assert.Equal(t, "src/main.go", sess.Results[0].File)
	assert.Equal(t, "config.yaml", sess.Results[1].File)
}

func TestOrgNameRegex(t *testing.T) {
	assert.True(t, orgNameRegex.MatchString("my-org"))
	assert.True(t, orgNameRegex.MatchString("my_org.name"))
	assert.True(t, orgNameRegex.MatchString("org123"))
	assert.False(t, orgNameRegex.MatchString("my org"))
	assert.False(t, orgNameRegex.MatchString("org/name"))
	assert.False(t, orgNameRegex.MatchString(""))
}

// --- Integration tests: actual scans ---

func TestRunLocalScan_Directory(t *testing.T) {
	// The default config excludes test directories (including "testdata"),
	// so scan the project root which contains non-test source files.
	projectRoot := filepath.Join(testdataDir(), "..")
	sc := NewScanner("", "")
	sess := &model.ScanSession{
		ID:        "test-local-dir",
		Request:   model.ScanRequest{Mode: model.ScanModeLocal, Target: projectRoot},
		Status:    model.ScanStatusRunning,
		Progress:  make(chan string, 256),
		Dismissed: make(map[int]bool),
	}

	sc.RunLocalScan(context.Background(), sess)

	assert.Equal(t, model.ScanStatusComplete, sess.Status)
	assert.Empty(t, sess.Error)
	assert.Greater(t, sess.Stats.FilesFound, 0)
	assert.Greater(t, sess.Stats.FilesScanned, 0)
}

func TestRunLocalScan_SingleFile(t *testing.T) {
	sc := NewScanner("", "")
	target := filepath.Join(testdataDir(), "dummy.go")
	sess := &model.ScanSession{
		ID:        "test-local-file",
		Request:   model.ScanRequest{Mode: model.ScanModeLocal, Target: target},
		Status:    model.ScanStatusRunning,
		Progress:  make(chan string, 256),
		Dismissed: make(map[int]bool),
	}

	sc.RunLocalScan(context.Background(), sess)

	assert.Equal(t, model.ScanStatusComplete, sess.Status)
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
	sess := &model.ScanSession{
		ID:        "test-local-yaml",
		Request:   model.ScanRequest{Mode: model.ScanModeLocal, Target: target},
		Status:    model.ScanStatusRunning,
		Progress:  make(chan string, 256),
		Dismissed: make(map[int]bool),
	}

	sc.RunLocalScan(context.Background(), sess)

	assert.Equal(t, model.ScanStatusComplete, sess.Status)
	assert.Greater(t, len(sess.Results), 0)

	var names []string
	for _, r := range sess.Results {
		names = append(names, r.Name)
	}
	assert.Contains(t, names, "accessKey")
}

func TestRunLocalScan_InvalidPath(t *testing.T) {
	sc := NewScanner("", "")
	sess := &model.ScanSession{
		ID:        "test-local-bad",
		Request:   model.ScanRequest{Mode: model.ScanModeLocal, Target: "/nonexistent/path/to/nowhere"},
		Status:    model.ScanStatusRunning,
		Progress:  make(chan string, 256),
		Dismissed: make(map[int]bool),
	}

	sc.RunLocalScan(context.Background(), sess)

	assert.Equal(t, model.ScanStatusFailed, sess.Status)
	assert.NotEmpty(t, sess.Error)
}

func TestRunRepoScan_InvalidURL(t *testing.T) {
	sc := NewScanner("", "")
	sess := &model.ScanSession{
		ID:        "test-repo-bad",
		Request:   model.ScanRequest{Mode: model.ScanModeRepo, Target: "ftp://evil.com/repo"},
		Status:    model.ScanStatusRunning,
		Progress:  make(chan string, 256),
		Dismissed: make(map[int]bool),
	}

	sc.RunRepoScan(context.Background(), sess)

	assert.Equal(t, model.ScanStatusFailed, sess.Status)
	assert.Contains(t, sess.Error, "Invalid URL")
}

func TestRunOrgScan_InvalidOrgName(t *testing.T) {
	sc := NewScanner("", "")
	sess := &model.ScanSession{
		ID:        "test-org-bad",
		Request:   model.ScanRequest{Mode: model.ScanModeOrg, Target: "invalid org name!"},
		Status:    model.ScanStatusRunning,
		Progress:  make(chan string, 256),
		Dismissed: make(map[int]bool),
	}

	sc.RunOrgScan(context.Background(), sess)

	assert.Equal(t, model.ScanStatusFailed, sess.Status)
	assert.Contains(t, sess.Error, "Invalid organization name")
}

// --- loadConfigWithOverride tests ---

func TestLoadConfigWithOverride_NilOverride(t *testing.T) {
	sc := NewScanner("", "")
	conf, err := sc.loadConfigWithOverride(nil)
	require.NoError(t, err)
	// Should return base defaults (minPasswordLength is 6 in default config)
	assert.Greater(t, conf.MinPasswordLength, 0)
}

func TestLoadConfigWithOverride_AppliesOverride(t *testing.T) {
	sc := NewScanner("", "")
	override := &config.Config{
		MinPasswordLength: 99,
		ScanTypes:         []string{config.ScanTypeGo},
	}
	conf, err := sc.loadConfigWithOverride(override)
	require.NoError(t, err)
	assert.Equal(t, 99, conf.MinPasswordLength)
	assert.Equal(t, []string{config.ScanTypeGo}, conf.ScanTypes)
}

func TestLoadConfigWithOverride_AppendsPatterns(t *testing.T) {
	sc := NewScanner("", "")
	override := &config.Config{
		VariableNamePatterns: []string{"(?i)myCustomPattern"},
	}
	conf, err := sc.loadConfigWithOverride(override)
	require.NoError(t, err)
	// Default has several patterns; override appends one more
	assert.Contains(t, conf.VariableNamePatterns, "(?i)myCustomPattern")
	assert.Greater(t, len(conf.VariableNamePatterns), 1)
}

// --- filterReposByPattern tests ---

func TestFilterReposByPattern_GlobMatch(t *testing.T) {
	repos := []repoInfo{
		{cloneURL: "https://github.com/org/my-service-api.git"},
		{cloneURL: "https://github.com/org/my-service-web.git"},
		{cloneURL: "https://github.com/org/other-project.git"},
		{cloneURL: "https://github.com/org/unrelated.git"},
	}

	filtered := filterReposByPattern(repos, "my-service-*")
	assert.Len(t, filtered, 2)
	assert.Equal(t, "https://github.com/org/my-service-api.git", filtered[0].cloneURL)
	assert.Equal(t, "https://github.com/org/my-service-web.git", filtered[1].cloneURL)
}

func TestFilterReposByPattern_NoMatch(t *testing.T) {
	repos := []repoInfo{
		{cloneURL: "https://github.com/org/repo-a.git"},
		{cloneURL: "https://github.com/org/repo-b.git"},
	}

	filtered := filterReposByPattern(repos, "nonexistent-*")
	assert.Empty(t, filtered)
}

func TestFilterReposByPattern_EmptyPattern(t *testing.T) {
	repos := []repoInfo{
		{cloneURL: "https://github.com/org/repo-a.git"},
		{cloneURL: "https://github.com/org/repo-b.git"},
	}

	// Empty pattern matches nothing (caller should skip filtering)
	filtered := filterReposByPattern(repos, "")
	assert.Empty(t, filtered)
}

func TestFilterReposByPattern_ExactMatch(t *testing.T) {
	repos := []repoInfo{
		{cloneURL: "https://github.com/org/exact-repo.git"},
		{cloneURL: "https://github.com/org/other.git"},
	}

	filtered := filterReposByPattern(repos, "exact-repo")
	assert.Len(t, filtered, 1)
	assert.Equal(t, "https://github.com/org/exact-repo.git", filtered[0].cloneURL)
}

func TestFilterReposByPattern_QuestionMarkGlob(t *testing.T) {
	repos := []repoInfo{
		{cloneURL: "https://github.com/org/api-v1.git"},
		{cloneURL: "https://github.com/org/api-v2.git"},
		{cloneURL: "https://github.com/org/api-v10.git"},
	}

	filtered := filterReposByPattern(repos, "api-v?")
	assert.Len(t, filtered, 2)
}
