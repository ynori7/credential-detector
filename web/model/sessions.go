package model

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

const sessionTimeout = 1 * time.Hour

// SessionStore holds active scan sessions in memory
type SessionStore struct {
	Mu       sync.RWMutex
	Sessions map[string]*ScanSession
}

// NewSessionStore creates a new session store and starts a cleanup goroutine
func NewSessionStore() *SessionStore {
	s := &SessionStore{
		Sessions: make(map[string]*ScanSession),
	}
	go s.cleanup()
	return s
}

// Create allocates a new scan session and returns it
func (s *SessionStore) Create(req ScanRequest) *ScanSession {
	id := GenerateID()
	session := &ScanSession{
		ID:        id,
		Request:   req,
		Status:    ScanStatusRunning,
		Progress:  make(chan string, 64),
		Dismissed: make(map[int]bool),
		CreatedAt: time.Now(),
	}
	s.Mu.Lock()
	s.Sessions[id] = session
	s.Mu.Unlock()
	return session
}

// Get retrieves a session by ID
func (s *SessionStore) Get(id string) (*ScanSession, bool) {
	s.Mu.RLock()
	defer s.Mu.RUnlock()
	sess, ok := s.Sessions[id]
	return sess, ok
}

// Delete removes a session from the store
func (s *SessionStore) Delete(id string) {
	s.Mu.Lock()
	delete(s.Sessions, id)
	s.Mu.Unlock()
}

func (s *SessionStore) cleanup() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.Mu.Lock()
		for id, sess := range s.Sessions {
			if sess.Status != ScanStatusRunning && time.Since(sess.CreatedAt) > sessionTimeout {
				delete(s.Sessions, id)
			}
		}
		s.Mu.Unlock()
	}
}

func GenerateID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("failed to generate session ID: " + err.Error())
	}
	return hex.EncodeToString(b)
}
