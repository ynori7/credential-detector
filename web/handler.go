package web

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/ynori7/credential-detector/config"
	"github.com/ynori7/credential-detector/web/model"
	"gopkg.in/yaml.v3"
)

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	defaults, err := s.scanner.DefaultConfig()
	if err != nil {
		http.Error(w, "Failed to load default configuration: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var override *config.Config
	if cookie, err := r.Cookie("config_id"); err == nil {
		override = s.configStore.Get(cookie.Value)
	}

	editorData := model.BuildEditorData(defaults, override)
	s.templates.ExecuteTemplate(w, "index.html", editorData)
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httpErrorHTML(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	mode := model.ScanMode(r.FormValue("mode"))
	target := strings.TrimSpace(r.FormValue("target"))
	depth := model.ScanDepth(r.FormValue("depth"))

	// Validate mode
	switch mode {
	case model.ScanModeRepo, model.ScanModeOrg, model.ScanModeLocal:
	default:
		httpErrorHTML(w, "Invalid scan mode", http.StatusBadRequest)
		return
	}

	if target == "" {
		httpErrorHTML(w, "Target is required", http.StatusBadRequest)
		return
	}

	// Local mode: validate the target is a filesystem path, not a URL
	if mode == model.ScanModeLocal {
		if strings.Contains(target, "://") || strings.Contains(target, "@") {
			httpErrorHTML(w, "Target must be a local file path, not a URL", http.StatusBadRequest)
			return
		}
		if !filepath.IsAbs(target) {
			httpErrorHTML(w, "Target must be an absolute file path", http.StatusBadRequest)
			return
		}
		// Deep scan doesn't apply to local paths
		depth = model.ScanDepthHead
	}

	if depth != model.ScanDepthHead && depth != model.ScanDepthDeep {
		depth = model.ScanDepthHead
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

	// Look up any saved config override from the session cookie
	var configOverride *config.Config
	if cookie, err := r.Cookie("config_id"); err == nil {
		configOverride = s.configStore.Get(cookie.Value)
	}

	req := model.ScanRequest{
		Mode:   mode,
		Target: target,
		Depth:  depth,
		OrgFilter: model.OrgFilter{
			ActiveOnly: r.FormValue("active_only") == "on",
		},
	}

	sess := s.sessions.Create(req)
	sess.ConfigOverride = configOverride

	// Start scan in background
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		defer func() {
			cancel()
			<-s.scanSem // release
		}()

		switch mode {
		case model.ScanModeRepo:
			s.scanner.RunRepoScan(ctx, sess)
		case model.ScanModeOrg:
			s.scanner.RunOrgScan(ctx, sess)
		case model.ScanModeLocal:
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
	fmt.Fprintf(w, `<article class="error-card"><header><h3>Error</h3></header><p>%s</p><a href="/">← Start a new scan</a></article>`, html.EscapeString(message))
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
				if sess.Status == model.ScanStatusFailed {
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
	s.templates.ExecuteTemplate(w, "results.html", model.ResultsPageData{
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

func (s *Server) handleDismissValue(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	value := r.URL.Query().Get("value")

	sess, ok := s.sessions.Get(id)
	if !ok {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	if value == "" {
		http.Error(w, "Value is required", http.StatusBadRequest)
		return
	}

	sess.DismissValue(value)

	w.Header().Set("Content-Type", "text/html")
	s.templates.ExecuteTemplate(w, "results.html", model.ResultsPageData{
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

// --- Config handlers ---

func (s *Server) handleConfigGet(w http.ResponseWriter, r *http.Request) {
	defaults, err := s.scanner.DefaultConfig()
	if err != nil {
		httpErrorHTML(w, "Failed to load default configuration: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var override *config.Config
	if cookie, err := r.Cookie("config_id"); err == nil {
		override = s.configStore.Get(cookie.Value)
	}

	editorData := model.BuildEditorData(defaults, override)
	w.Header().Set("Content-Type", "text/html")
	s.templates.ExecuteTemplate(w, "config_editor.html", editorData)
}

func (s *Server) handleConfigSave(w http.ResponseWriter, r *http.Request) {
	override, err := parseConfigFromForm(r)
	if err != nil {
		httpErrorHTML(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := validateConfig(override); err != nil {
		httpErrorHTML(w, "Validation error: "+err.Error(), http.StatusBadRequest)
		return
	}

	id := s.configStore.Save(override)
	http.SetCookie(w, &http.Cookie{
		Name:     "config_id",
		Value:    id,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
		HttpOnly: true,
	})

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, `<p class="config-saved-notice" role="status">&#10003; Configuration applied. It will be used for your next scan.</p>`)
}

func (s *Server) handleConfigDelete(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("config_id"); err == nil {
		s.configStore.Delete(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "config_id",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	defaults, err := s.scanner.DefaultConfig()
	if err != nil {
		httpErrorHTML(w, "Failed to load default configuration: "+err.Error(), http.StatusInternalServerError)
		return
	}

	editorData := model.BuildEditorData(defaults, nil)
	w.Header().Set("Content-Type", "text/html")
	s.templates.ExecuteTemplate(w, "config_editor.html", editorData)
}

func (s *Server) handleConfigExport(w http.ResponseWriter, r *http.Request) {
	// Parse the form so the download always reflects the current form state,
	// not just the last saved override.
	conf, err := parseConfigFromForm(r)
	if err != nil {
		http.Error(w, "Failed to parse config: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateConfig(conf); err != nil {
		http.Error(w, "Validation error: "+err.Error(), http.StatusBadRequest)
		return
	}

	data, err := yaml.Marshal(conf)
	if err != nil {
		http.Error(w, "Failed to marshal config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("Content-Disposition", `attachment; filename="credential-detector-config.yaml"`)
	w.Write(data)
}

// --- Config form parsing helpers ---

func parseConfigFromForm(r *http.Request) (*config.Config, error) {
	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("invalid form data")
	}

	c := &config.Config{}

	// Append fields (textarea, one item per line)
	c.VariableNamePatterns = splitLines(r.FormValue("variableNamePatterns"))
	c.VariableValueExcludePatterns = splitLines(r.FormValue("variableValueExcludePatterns"))
	c.FullTextValueExcludePatterns = splitLines(r.FormValue("fullTextValueExcludePatterns"))
	c.TestDirectories = splitLines(r.FormValue("testDirectories"))
	c.IgnoreFiles = splitLines(r.FormValue("ignoreFiles"))
	c.GenericFileExtensions = splitLines(r.FormValue("genericFileExtensions"))
	c.GenericCodeFileExtensions = splitLines(r.FormValue("genericCodeFileExtensions"))

	// ValueMatchPatterns: indexed fields vmpName[N] / vmpPattern[N]
	for key, vals := range r.Form {
		if !strings.HasPrefix(key, "vmpName[") || !strings.HasSuffix(key, "]") {
			continue
		}
		idx := key[len("vmpName[") : len(key)-1]
		name := strings.TrimSpace(vals[0])
		pattern := strings.TrimSpace(r.FormValue("vmpPattern[" + idx + "]"))
		if name != "" && pattern != "" {
			c.ValueMatchPatterns = append(c.ValueMatchPatterns, config.ValueMatchPattern{
				Name:    name,
				Pattern: pattern,
			})
		}
	}

	// Replace fields
	c.VariableNameExclusionPattern = strings.TrimSpace(r.FormValue("variableNameExclusionPattern"))
	c.XMLAttributeNameExclusionPattern = strings.TrimSpace(r.FormValue("xmlAttributeNameExclusionPattern"))

	if mpStr := strings.TrimSpace(r.FormValue("minPasswordLength")); mpStr != "" {
		mp, err := strconv.Atoi(mpStr)
		if err != nil || mp < 0 {
			return nil, fmt.Errorf("minPasswordLength must be a non-negative integer")
		}
		c.MinPasswordLength = mp
	}

	c.ExcludeTests = r.FormValue("excludeTests") == "on"
	c.ExcludeComments = r.FormValue("excludeComments") == "on"
	c.Verbose = r.FormValue("verbose") == "on"

	c.ScanTypes = r.Form["scanTypes"]

	return c, nil
}

func validateConfig(c *config.Config) error {
	validScanTypes := make(map[string]bool)
	for _, st := range model.AllScanTypes {
		validScanTypes[st] = true
	}

	for _, st := range c.ScanTypes {
		if !validScanTypes[st] {
			return fmt.Errorf("unknown scan type: %q", st)
		}
	}
	if len(c.ScanTypes) == 0 && len(model.AllScanTypes) > 0 {
		// Empty scan types is allowed (means "keep root defaults")
	}

	for i, p := range c.VariableNamePatterns {
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("variableNamePatterns[%d] is not a valid regex: %v", i, err)
		}
	}
	for _, vmp := range c.ValueMatchPatterns {
		if _, err := regexp.Compile(vmp.Pattern); err != nil {
			return fmt.Errorf("value match pattern %q has invalid regex: %v", vmp.Name, err)
		}
	}
	for i, p := range c.VariableValueExcludePatterns {
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("variableValueExcludePatterns[%d] is not a valid regex: %v", i, err)
		}
	}
	for i, p := range c.FullTextValueExcludePatterns {
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("fullTextValueExcludePatterns[%d] is not a valid regex: %v", i, err)
		}
	}
	if c.VariableNameExclusionPattern != "" {
		if _, err := regexp.Compile(c.VariableNameExclusionPattern); err != nil {
			return fmt.Errorf("variableNameExclusionPattern is not a valid regex: %v", err)
		}
	}
	if c.XMLAttributeNameExclusionPattern != "" {
		if _, err := regexp.Compile(c.XMLAttributeNameExclusionPattern); err != nil {
			return fmt.Errorf("xmlAttributeNameExclusionPattern is not a valid regex: %v", err)
		}
	}

	return nil
}

// splitLines splits a string by newlines, trimming whitespace and empty lines.
func splitLines(s string) []string {
	var result []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}
