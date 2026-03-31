package model

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

	Mu        sync.Mutex
	Dismissed map[int]bool
}

// DismissFile marks all results for a given file as dismissed
func (s *ScanSession) DismissFile(file string) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	if s.Dismissed == nil {
		s.Dismissed = make(map[int]bool)
	}
	for i, r := range s.Results {
		if r.File == file {
			s.Dismissed[i] = true
		}
	}
}

// DismissValue marks all results with the given value as dismissed
func (s *ScanSession) DismissValue(value string) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	if s.Dismissed == nil {
		s.Dismissed = make(map[int]bool)
	}
	for i, r := range s.Results {
		if r.Value == value {
			s.Dismissed[i] = true
		}
	}
}

// Dismiss marks a result index as dismissed
func (s *ScanSession) Dismiss(index int) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	if s.Dismissed == nil {
		s.Dismissed = make(map[int]bool)
	}
	s.Dismissed[index] = true
}

// IsDismissed checks whether a result has been dismissed
func (s *ScanSession) IsDismissed(index int) bool {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	return s.Dismissed[index]
}

// ActiveResults returns non-dismissed results with their original indices
func (s *ScanSession) ActiveResults() []IndexedResult {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	var active []IndexedResult
	for i, r := range s.Results {
		if !s.Dismissed[i] {
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
