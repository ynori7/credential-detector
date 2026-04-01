package web

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/ynori7/credential-detector/config"
	"github.com/ynori7/credential-detector/parser"
	"github.com/ynori7/credential-detector/web/model"
)

var (
	orgNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)
	// Only allow well-known Git hosting providers
	allowedHosts = []string{"github.com", "gitlab.com", "bitbucket.org"}

	// Sensitive system paths that must not be scanned via the web UI
	deniedLocalPrefixes = []string{
		"/etc",
		"/root",
		"/proc",
		"/sys",
		"/dev",
		"/run",
		"/boot",
		"/private/etc", // macOS
		"/private/var", // macOS
		"/Users/root",
	}
)

// Scanner handles cloning and scanning operations
type Scanner struct {
	configPath     string
	rootConfigPath string
}

// NewScanner creates a scanner with optional config overrides
func NewScanner(configPath, rootConfigPath string) *Scanner {
	return &Scanner{
		configPath:     configPath,
		rootConfigPath: rootConfigPath,
	}
}

func (sc *Scanner) loadConfig() (*config.Config, error) {
	return config.LoadConfig(sc.configPath, sc.rootConfigPath)
}

// DefaultConfig returns the effective base configuration (no session override applied).
func (sc *Scanner) DefaultConfig() (*config.Config, error) {
	return sc.loadConfig()
}

// loadConfigWithOverride loads the base config and merges the session's config override on top.
func (sc *Scanner) loadConfigWithOverride(override *config.Config) (*config.Config, error) {
	conf, err := sc.loadConfig()
	if err != nil || override == nil {
		return conf, err
	}
	return config.MergeConfigs(conf, override), nil
}

// RunRepoScan clones a repo and scans it, sending progress to the session
func (sc *Scanner) RunRepoScan(ctx context.Context, sess *model.ScanSession) {
	defer close(sess.Progress)

	target := sess.Request.Target

	if err := validateRepoURL(target); err != nil {
		sc.failSession(sess, fmt.Sprintf("Invalid URL: %s", err))
		return
	}

	conf, err := sc.loadConfigWithOverride(sess.ConfigOverride)
	if err != nil {
		sc.failSession(sess, fmt.Sprintf("Failed to load config: %s", err))
		return
	}

	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "credential-detector-*")
	if err != nil {
		sc.failSession(sess, fmt.Sprintf("Failed to create temp directory: %s", err))
		return
	}
	defer os.RemoveAll(tmpDir)

	repoDir := filepath.Join(tmpDir, "repo")

	sess.Progress <- fmt.Sprintf("Cloning %s ...", target)

	deep := sess.Request.Depth == model.ScanDepthDeep
	if err := cloneRepo(ctx, target, repoDir, deep); err != nil {
		sc.failSession(sess, fmt.Sprintf("Clone failed: %s", err))
		return
	}

	sess.Progress <- "Clone complete. Starting scan..."

	if deep {
		sc.runDeepScan(ctx, sess, conf, repoDir)
	} else {
		sc.runHeadScan(ctx, sess, conf, repoDir)
	}

	// Clean up file paths — strip temp dir prefix to show repo-relative paths
	sc.stripFilePrefix(sess, repoDir)
}

// RunOrgScan lists repos in an org and scans each one
func (sc *Scanner) RunOrgScan(ctx context.Context, sess *model.ScanSession) {
	defer close(sess.Progress)

	orgName := sess.Request.Target
	if !orgNameRegex.MatchString(orgName) {
		sc.failSession(sess, "Invalid organization name. Only alphanumeric characters, hyphens, underscores, and dots are allowed.")
		return
	}

	conf, err := sc.loadConfigWithOverride(sess.ConfigOverride)
	if err != nil {
		sc.failSession(sess, fmt.Sprintf("Failed to load config: %s", err))
		return
	}

	sess.Progress <- fmt.Sprintf("Fetching repos for org '%s' ...", orgName)

	repos, err := listOrgRepos(ctx, orgName)
	if err != nil {
		sc.failSession(sess, fmt.Sprintf("Failed to list org repos: %s", err))
		return
	}

	sess.Progress <- fmt.Sprintf("Found %d repos in '%s'", len(repos), orgName)

	if sess.Request.OrgFilter.ActiveOnly {
		cutoff := time.Now().AddDate(0, -6, 0)
		var filtered []repoInfo
		for _, r := range repos {
			if !r.pushedAt.IsZero() && r.pushedAt.After(cutoff) {
				filtered = append(filtered, r)
			}
		}
		sess.Progress <- fmt.Sprintf("Filtered to %d active repos (pushed within the last 6 months)", len(filtered))
		repos = filtered
	}

	if pattern := sess.Request.OrgFilter.RepoPattern; pattern != "" {
		repos = filterReposByPattern(repos, pattern)
		sess.Progress <- fmt.Sprintf("Filtered to %d repos matching pattern '%s'", len(repos), pattern)
	}

	var allResults []parser.Result
	var totalStats parser.Statistics

	for i, repo := range repos {
		repoURL := repo.cloneURL
		if ctx.Err() != nil {
			sc.failSession(sess, "Scan cancelled")
			return
		}

		sess.Progress <- fmt.Sprintf("[%d/%d] Cloning %s ...", i+1, len(repos), repoURL)

		tmpDir, err := os.MkdirTemp("", "credential-detector-*")
		if err != nil {
			sess.Progress <- fmt.Sprintf("  Skipping %s: failed to create temp dir: %s", repoURL, err)
			continue
		}

		repoDir := filepath.Join(tmpDir, "repo")

		if err := cloneRepo(ctx, repoURL, repoDir, false); err != nil {
			sess.Progress <- fmt.Sprintf("  Skipping %s: clone failed: %s", repoURL, err)
			os.RemoveAll(tmpDir)
			continue
		}

		sess.Progress <- fmt.Sprintf("[%d/%d] Scanning %s ...", i+1, len(repos), repoURL)

		p := parser.NewParser(conf)
		if err := p.Scan(repoDir); err != nil {
			sess.Progress <- fmt.Sprintf("  Scan error for %s: %s", repoURL, err)
			os.RemoveAll(tmpDir)
			continue
		}

		// Strip temp dir prefix and prefix results with repo name for clarity
		repoName := repoNameFromURL(repoURL)
		for j := range p.Results {
			relPath := strings.TrimPrefix(p.Results[j].File, repoDir)
			relPath = strings.TrimPrefix(relPath, string(filepath.Separator))
			p.Results[j].File = repoName + "/" + relPath
		}

		allResults = append(allResults, p.Results...)
		totalStats.FilesFound += p.Statistics.FilesFound
		totalStats.FilesScanned += p.Statistics.FilesScanned
		totalStats.ResultsFound += p.Statistics.ResultsFound

		sess.Progress <- fmt.Sprintf("[%d/%d] Found %d results in %s", i+1, len(repos), p.Statistics.ResultsFound, repoURL)

		os.RemoveAll(tmpDir)
	}

	sortResults(allResults)
	sess.Mu.Lock()
	sess.Results = allResults
	sess.Stats = totalStats
	sess.Status = model.ScanStatusComplete
	sess.Mu.Unlock()

	sess.Progress <- "done"
}

// RunLocalScan scans a local directory or file
func (sc *Scanner) RunLocalScan(ctx context.Context, sess *model.ScanSession) {
	defer close(sess.Progress)

	target := sess.Request.Target

	// Block sensitive system directories
	if err := validateLocalPath(target); err != nil {
		sc.failSession(sess, fmt.Sprintf("Forbidden path: %s", err))
		return
	}

	// Validate path exists
	info, err := os.Stat(target)
	if err != nil {
		sc.failSession(sess, fmt.Sprintf("Invalid path: %s", err))
		return
	}
	_ = info

	conf, err := sc.loadConfigWithOverride(sess.ConfigOverride)
	if err != nil {
		sc.failSession(sess, fmt.Sprintf("Failed to load config: %s", err))
		return
	}

	sess.Progress <- fmt.Sprintf("Scanning %s ...", target)

	sc.runHeadScan(ctx, sess, conf, target)
}

func (sc *Scanner) runHeadScan(_ context.Context, sess *model.ScanSession, conf *config.Config, scanPath string) {
	p := parser.NewParser(conf)
	if err := p.Scan(scanPath); err != nil {
		sc.failSession(sess, fmt.Sprintf("Scan failed: %s", err))
		return
	}

	sortResults(p.Results)
	sess.Mu.Lock()
	sess.Results = p.Results
	sess.Stats = p.Statistics
	sess.Status = model.ScanStatusComplete
	sess.Mu.Unlock()

	sess.Progress <- "done"
}

func (sc *Scanner) runDeepScan(_ context.Context, sess *model.ScanSession, conf *config.Config, scanPath string) {
	repo, err := git.PlainOpen(scanPath)
	if err != nil {
		sc.failSession(sess, fmt.Sprintf("Failed to open git repo: %s", err))
		return
	}

	ref, err := repo.Head()
	if err != nil {
		sc.failSession(sess, fmt.Sprintf("Failed to get HEAD: %s", err))
		return
	}
	refHash := ref.Hash()

	commitIter, err := repo.Log(&git.LogOptions{From: refHash})
	if err != nil {
		sc.failSession(sess, fmt.Sprintf("Failed to get commit log: %s", err))
		return
	}

	resultsSet := make(map[string]struct{})
	var allResults []parser.Result
	var totalStats parser.Statistics
	commitCount := 0

	err = commitIter.ForEach(func(c *object.Commit) error {
		commitCount++
		commitShort := c.Hash.String()[:8]
		sess.Progress <- fmt.Sprintf("Scanning commit %d: %s", commitCount, commitShort)

		worktree, err := repo.Worktree()
		if err != nil {
			return err
		}

		if err := worktree.Checkout(&git.CheckoutOptions{Hash: c.Hash}); err != nil {
			return err
		}

		p := parser.NewParser(conf)
		if err := p.Scan(scanPath); err != nil {
			return err
		}

		for _, result := range p.Results {
			if _, exists := resultsSet[result.Value]; !exists {
				resultsSet[result.Value] = struct{}{}
				// Tag the file path with the commit where this credential was found
				relPath := strings.TrimPrefix(result.File, scanPath)
				relPath = strings.TrimPrefix(relPath, string(filepath.Separator))
				result.File = fmt.Sprintf("[%s] %s", commitShort, relPath)
				allResults = append(allResults, result)
			}
		}

		totalStats.FilesFound += p.Statistics.FilesFound
		totalStats.FilesScanned += p.Statistics.FilesScanned

		// Reset back to HEAD
		if err := worktree.Reset(&git.ResetOptions{Mode: git.HardReset, Commit: refHash}); err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		sc.failSession(sess, fmt.Sprintf("Deep scan error: %s", err))
		return
	}

	totalStats.ResultsFound = len(allResults)
	sortResults(allResults)

	sess.Mu.Lock()
	sess.Results = allResults
	sess.Stats = totalStats
	sess.Status = model.ScanStatusComplete
	sess.Mu.Unlock()

	sess.Progress <- "done"
}

func (sc *Scanner) stripFilePrefix(sess *model.ScanSession, prefix string) {
	sess.Mu.Lock()
	defer sess.Mu.Unlock()
	for i := range sess.Results {
		rel := strings.TrimPrefix(sess.Results[i].File, prefix)
		sess.Results[i].File = strings.TrimPrefix(rel, string(filepath.Separator))
	}
}

func (sc *Scanner) failSession(sess *model.ScanSession, msg string) {
	sess.Mu.Lock()
	sess.Status = model.ScanStatusFailed
	sess.Error = msg
	sess.Mu.Unlock()
	sess.Progress <- "error: " + msg
}

// --- Helpers ---

func cloneRepo(ctx context.Context, repoURL, destDir string, deep bool) error {
	var cmd *exec.Cmd
	if isGitHubURL(repoURL) {
		cmd = exec.CommandContext(ctx, "gh", "repo", "clone", repoURL, destDir)
	} else if deep {
		cmd = exec.CommandContext(ctx, "git", "clone", repoURL, destDir)
	} else {
		cmd = exec.CommandContext(ctx, "git", "clone", "--depth=1", repoURL, destDir)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, string(output))
	}
	return nil
}

func isGitHubURL(u string) bool {
	return strings.Contains(u, "github.com") || (!strings.Contains(u, "://") && !strings.Contains(u, "@"))
}

func validateRepoURL(rawURL string) error {
	// Allow GitHub shorthand (owner/repo) used by gh CLI
	if orgNameRegex.MatchString(strings.ReplaceAll(rawURL, "/", "")) && strings.Count(rawURL, "/") == 1 {
		return nil
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("cannot parse URL: %w", err)
	}

	// Only allow https and ssh schemes
	switch parsed.Scheme {
	case "https", "ssh", "git+ssh":
		// ok
	default:
		return fmt.Errorf("unsupported scheme: %s (only https and ssh are allowed)", parsed.Scheme)
	}

	// Only allow well-known Git hosting providers
	hostname := strings.ToLower(parsed.Hostname())
	allowed := false
	for _, h := range allowedHosts {
		if hostname == h {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("unsupported host: %s (only github.com, gitlab.com, and bitbucket.org are allowed)", hostname)
	}

	return nil
}

// repoInfo holds basic metadata about a GitHub repository.
type repoInfo struct {
	cloneURL string
	pushedAt time.Time
}

func listOrgRepos(ctx context.Context, orgName string) ([]repoInfo, error) {
	// jq expression emits "<clone_url>|<pushed_at>" per repo, one per line
	cmd := exec.CommandContext(ctx, "gh", "api",
		fmt.Sprintf("/orgs/%s/repos", orgName),
		"--paginate",
		"--jq", `.[] | (.clone_url + "|" + (.pushed_at // ""))`,
	)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("gh api failed: %w", err)
	}

	var repos []repoInfo
	sc := bufio.NewScanner(strings.NewReader(string(output)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 2)
		info := repoInfo{cloneURL: parts[0]}
		if len(parts) == 2 && parts[1] != "" && parts[1] != "null" {
			if t, err := time.Parse(time.RFC3339, parts[1]); err == nil {
				info.pushedAt = t
			}
		}
		repos = append(repos, info)
	}

	// Fallback: parse as JSON array (some gh versions don't support --jq filtering)
	if len(repos) == 0 && len(output) > 0 {
		var jsonRepos []struct {
			CloneURL string `json:"clone_url"`
			PushedAt string `json:"pushed_at"`
		}
		if err := json.Unmarshal(output, &jsonRepos); err == nil {
			for _, r := range jsonRepos {
				info := repoInfo{cloneURL: r.CloneURL}
				if r.PushedAt != "" {
					if t, err := time.Parse(time.RFC3339, r.PushedAt); err == nil {
						info.pushedAt = t
					}
				}
				repos = append(repos, info)
			}
		}
	}

	return repos, nil
}

func repoNameFromURL(repoURL string) string {
	// Extract repo name from URL like https://github.com/owner/repo.git
	name := filepath.Base(repoURL)
	return strings.TrimSuffix(name, ".git")
}

func sortResults(results []parser.Result) {
	sort.Slice(results, func(i, j int) bool {
		if results[i].File == results[j].File {
			if results[i].Line == results[j].Line {
				return results[i].Name < results[j].Name
			}
			return results[i].Line < results[j].Line
		}
		return results[i].File < results[j].File
	})
}

func validateLocalPath(target string) error {
	// Resolve symlinks and clean the path to prevent traversal bypasses
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		// Path may not exist yet; fall back to lexical clean
		resolved = filepath.Clean(target)
	}
	for _, prefix := range deniedLocalPrefixes {
		if resolved == prefix || strings.HasPrefix(resolved, prefix+string(filepath.Separator)) {
			return fmt.Errorf("scanning %q is not permitted", resolved)
		}
	}
	return nil
}

// filterReposByPattern filters repos by matching the repo name against a glob pattern.
func filterReposByPattern(repos []repoInfo, pattern string) []repoInfo {
	var filtered []repoInfo
	for _, r := range repos {
		name := repoNameFromURL(r.cloneURL)
		if matched, err := path.Match(pattern, name); err == nil && matched {
			filtered = append(filtered, r)
		}
	}
	return filtered
}
