package web

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ynori7/credential-detector/parser"
)

// --- ScanSession tests ---

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
