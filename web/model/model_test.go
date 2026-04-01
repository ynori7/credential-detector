package model

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ynori7/credential-detector/parser"
)

// --- ScanSession tests ---

func TestScanSession_Dismiss(t *testing.T) {
	sess := &ScanSession{
		Results:   make([]parser.Result, 3),
		Dismissed: make(map[int]bool),
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
		Dismissed: make(map[int]bool),
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

func TestScanSession_DismissValue(t *testing.T) {
	sess := &ScanSession{
		Results: []parser.Result{
			{File: "a.go", Name: "key1", Value: "secret123"},
			{File: "b.go", Name: "key2", Value: "other"},
			{File: "c.go", Name: "key3", Value: "secret123"},
		},
		Dismissed: make(map[int]bool),
	}

	sess.DismissValue("secret123")

	assert.True(t, sess.IsDismissed(0))
	assert.False(t, sess.IsDismissed(1))
	assert.True(t, sess.IsDismissed(2))
}

func TestScanSession_DismissValue_NilMap(t *testing.T) {
	sess := &ScanSession{
		Results: []parser.Result{
			{File: "a.go", Value: "secret123"},
		},
	}

	// DismissValue should initialize the dismissed map
	sess.DismissValue("secret123")
	assert.True(t, sess.IsDismissed(0))
}

func TestScanSession_DismissValue_NoMatch(t *testing.T) {
	sess := &ScanSession{
		Results: []parser.Result{
			{File: "a.go", Value: "secret123"},
		},
		Dismissed: make(map[int]bool),
	}

	sess.DismissValue("doesnotexist")
	assert.False(t, sess.IsDismissed(0))
}

// --- SessionStore tests ---

func TestSessionStore_CreateAndGet(t *testing.T) {
	store := &SessionStore{Sessions: make(map[string]*ScanSession)}
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
	store := &SessionStore{Sessions: make(map[string]*ScanSession)}
	_, ok := store.Get("nonexistent")
	assert.False(t, ok)
}

func TestSessionStore_Delete(t *testing.T) {
	store := &SessionStore{Sessions: make(map[string]*ScanSession)}
	sess := store.Create(ScanRequest{Mode: ScanModeLocal, Target: "/tmp"})

	store.Delete(sess.ID)
	_, ok := store.Get(sess.ID)
	assert.False(t, ok)
}

// --- ExportData tests ---

func TestExportData_JSONRoundTrip(t *testing.T) {
	original := ExportData{
		Version:    1,
		ExportedAt: time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC),
		Request: ScanRequest{
			Mode:   ScanModeOrg,
			Target: "my-org",
			Depth:  ScanDepthHead,
			OrgFilter: OrgFilter{
				ActiveOnly:  true,
				RepoPattern: "my-service-*",
			},
		},
		Results: []parser.Result{
			{File: "repo/config.go", Type: 1, Line: 10, Name: "apiKey", Value: "secret123", CredentialType: "API Key"},
			{File: "repo/main.go", Type: 2, Line: 25, Name: "password", Value: "pass456"},
		},
		Stats: parser.Statistics{
			FilesFound:   100,
			FilesScanned: 80,
			ResultsFound: 2,
		},
		Dismissed: map[int]bool{0: true},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var restored ExportData
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)

	assert.Equal(t, original.Version, restored.Version)
	assert.Equal(t, original.ExportedAt, restored.ExportedAt)
	assert.Equal(t, original.Request.Mode, restored.Request.Mode)
	assert.Equal(t, original.Request.Target, restored.Request.Target)
	assert.Equal(t, original.Request.OrgFilter.ActiveOnly, restored.Request.OrgFilter.ActiveOnly)
	assert.Equal(t, original.Request.OrgFilter.RepoPattern, restored.Request.OrgFilter.RepoPattern)
	assert.Len(t, restored.Results, 2)
	assert.Equal(t, "apiKey", restored.Results[0].Name)
	assert.Equal(t, "secret123", restored.Results[0].Value)
	assert.Equal(t, "API Key", restored.Results[0].CredentialType)
	assert.Equal(t, 10, restored.Results[0].Line)
	assert.Equal(t, original.Stats, restored.Stats)
	assert.True(t, restored.Dismissed[0])
	assert.False(t, restored.Dismissed[1])
}
