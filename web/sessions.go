package web

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

const sessionTimeout = 1 * time.Hour

// SessionStore holds active scan sessions in memory
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*ScanSession
}

// NewSessionStore creates a new session store and starts a cleanup goroutine
func NewSessionStore() *SessionStore {
	s := &SessionStore{
		sessions: make(map[string]*ScanSession),
	}
	go s.cleanup()
	return s
}

// Create allocates a new scan session and returns it
func (s *SessionStore) Create(req ScanRequest) *ScanSession {
	id := generateID()
	session := &ScanSession{
		ID:        id,
		Request:   req,
		Status:    ScanStatusRunning,
		Progress:  make(chan string, 64),
		dismissed: make(map[int]bool),
		CreatedAt: time.Now(),
	}
	s.mu.Lock()
	s.sessions[id] = session
	s.mu.Unlock()
	return session
}

// Get retrieves a session by ID
func (s *SessionStore) Get(id string) (*ScanSession, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[id]
	return sess, ok
}

// Delete removes a session from the store
func (s *SessionStore) Delete(id string) {
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
}

func (s *SessionStore) cleanup() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		for id, sess := range s.sessions {
			if sess.Status != ScanStatusRunning && time.Since(sess.CreatedAt) > sessionTimeout {
				delete(s.sessions, id)
			}
		}
		s.mu.Unlock()
	}
}

func generateID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("failed to generate session ID: " + err.Error())
	}
	return hex.EncodeToString(b)
}
