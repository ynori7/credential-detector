package web

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
)

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	s.templates.ExecuteTemplate(w, "index.html", nil)
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httpErrorHTML(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	mode := ScanMode(r.FormValue("mode"))
	target := strings.TrimSpace(r.FormValue("target"))
	depth := ScanDepth(r.FormValue("depth"))

	// Validate mode
	switch mode {
	case ScanModeRepo, ScanModeOrg, ScanModeLocal:
	default:
		httpErrorHTML(w, "Invalid scan mode", http.StatusBadRequest)
		return
	}

	if target == "" {
		httpErrorHTML(w, "Target is required", http.StatusBadRequest)
		return
	}

	// Local mode: validate the target is a filesystem path, not a URL
	if mode == ScanModeLocal {
		if strings.Contains(target, "://") || strings.Contains(target, "@") {
			httpErrorHTML(w, "Target must be a local file path, not a URL", http.StatusBadRequest)
			return
		}
		if !filepath.IsAbs(target) {
			httpErrorHTML(w, "Target must be an absolute file path", http.StatusBadRequest)
			return
		}
		// Deep scan doesn't apply to local paths
		depth = ScanDepthHead
	}

	if depth != ScanDepthHead && depth != ScanDepthDeep {
		depth = ScanDepthHead
	}

	// Try to acquire the scan semaphore (only 1 scan at a time)
	select {
	case s.scanSem <- struct{}{}:
		// acquired
	default:
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `<div class="notice" role="alert">A scan is already in progress. Please wait for it to complete.</div>`)
		return
	}

	req := ScanRequest{
		Mode:   mode,
		Target: target,
		Depth:  depth,
	}

	sess := s.sessions.Create(req)

	// Start scan in background
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		defer func() {
			cancel()
			<-s.scanSem // release
		}()

		switch mode {
		case ScanModeRepo:
			s.scanner.RunRepoScan(ctx, sess)
		case ScanModeOrg:
			s.scanner.RunOrgScan(ctx, sess)
		case ScanModeLocal:
			s.scanner.RunLocalScan(ctx, sess)
		}
	}()

	// Return the progress partial which will connect to SSE
	w.Header().Set("Content-Type", "text/html")
	s.templates.ExecuteTemplate(w, "progress.html", map[string]string{
		"SessionID": sess.ID,
	})
}

// httpErrorHTML writes an HTML error card with the given status code.
// This allows HTMX to swap the response into the page when configured to
// accept non-2xx responses.
func httpErrorHTML(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	fmt.Fprintf(w, `<article class="error-card"><header><h3>Error</h3></header><p>%s</p><a href="/">← Start a new scan</a></article>`, message)
}

func (s *Server) handleProgress(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	sess, ok := s.sessions.Get(id)
	if !ok {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	ctx := r.Context()

	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-sess.Progress:
			if !ok {
				// Channel closed — scan is done
				if sess.Status == ScanStatusFailed {
				fmt.Fprintf(w, "event: scan-error\ndata: %s\n\n", sess.Error)
				} else {
					fmt.Fprintf(w, "event: complete\ndata: %s\n\n", sess.ID)
				}
				flusher.Flush()
				return
			}
			fmt.Fprintf(w, "event: progress\ndata: %s\n\n", msg)
			flusher.Flush()
		}
	}
}

func (s *Server) handleResults(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	sess, ok := s.sessions.Get(id)
	if !ok {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	s.templates.ExecuteTemplate(w, "results.html", ResultsPageData{
		SessionID:   sess.ID,
		Results:     sess.ActiveResults(),
		Stats:       sess.Stats,
		Status:      sess.Status,
		Error:       sess.Error,
		Target:      sess.Request.Target,
		ActiveCount: len(sess.ActiveResults()),
		TotalCount:  len(sess.Results),
	})
}

func (s *Server) handleDismiss(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	indexStr := r.PathValue("index")

	sess, ok := s.sessions.Get(id)
	if !ok {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	index, err := strconv.Atoi(indexStr)
	if err != nil || index < 0 || index >= len(sess.Results) {
		http.Error(w, "Invalid index", http.StatusBadRequest)
		return
	}

	sess.Dismiss(index)

	// Return an empty HTML comment so HTMX processes the outerHTML swap
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte("<!-- dismissed -->"))
}

func (s *Server) handleDismissFile(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	file := r.URL.Query().Get("file")

	sess, ok := s.sessions.Get(id)
	if !ok {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	if file == "" {
		http.Error(w, "File is required", http.StatusBadRequest)
		return
	}

	sess.DismissFile(file)

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte("<!-- dismissed -->"))
}
