package web

import (
	"sync"
	"time"

	"github.com/ynori7/credential-detector/config"
	"github.com/ynori7/credential-detector/parser"
)

// ScanMode indicates what kind of scan to perform
type ScanMode string

const (
	ScanModeRepo  ScanMode = "repo"
	ScanModeOrg   ScanMode = "org"
	ScanModeLocal ScanMode = "local"
)

// ScanDepth indicates how deep the scan should go
type ScanDepth string

const (
	ScanDepthHead ScanDepth = "head"
	ScanDepthDeep ScanDepth = "deep"
)

// ScanStatus tracks the lifecycle of a scan
type ScanStatus string

const (
	ScanStatusRunning  ScanStatus = "running"
	ScanStatusComplete ScanStatus = "complete"
	ScanStatusFailed   ScanStatus = "failed"
)

// ScanRequest represents a user-submitted scan form
type ScanRequest struct {
	Mode   ScanMode
	Target string
	Depth  ScanDepth
}

// ScanSession holds the state of an in-progress or completed scan
type ScanSession struct {
	ID             string
	Request        ScanRequest
	Status         ScanStatus
	Error          string
	Results        []parser.Result
	Stats          parser.Statistics
	Progress       chan string
	CreatedAt      time.Time
	ConfigOverride *config.Config // optional per-session config additions

	mu        sync.Mutex
	dismissed map[int]bool
}

// DismissFile marks all results for a given file as dismissed
func (s *ScanSession) DismissFile(file string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dismissed == nil {
		s.dismissed = make(map[int]bool)
	}
	for i, r := range s.Results {
		if r.File == file {
			s.dismissed[i] = true
		}
	}
}

// Dismiss marks a result index as dismissed
func (s *ScanSession) Dismiss(index int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dismissed == nil {
		s.dismissed = make(map[int]bool)
	}
	s.dismissed[index] = true
}

// IsDismissed checks whether a result has been dismissed
func (s *ScanSession) IsDismissed(index int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dismissed[index]
}

// ActiveResults returns non-dismissed results with their original indices
func (s *ScanSession) ActiveResults() []IndexedResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	var active []IndexedResult
	for i, r := range s.Results {
		if !s.dismissed[i] {
			active = append(active, IndexedResult{Index: i, Result: r})
		}
	}
	return active
}

// IndexedResult pairs a result with its original index for dismiss operations
type IndexedResult struct {
	Index  int
	Result parser.Result
}

// ResultRowData is passed into the result_row template
type ResultRowData struct {
	SessionID string
	Index     int
	Result    parser.Result
}

// ResultsPageData is passed into the results template
type ResultsPageData struct {
	SessionID   string
	Results     []IndexedResult
	Stats       parser.Statistics
	Status      ScanStatus
	Error       string
	Target      string
	ActiveCount int
	TotalCount  int
}
