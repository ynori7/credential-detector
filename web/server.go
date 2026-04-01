package web

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"
	"strings"

	"github.com/ynori7/credential-detector/parser"
	"github.com/ynori7/credential-detector/web/model"
)

//go:embed templates/*
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

// Server is the web UI HTTP server
type Server struct {
	mux         *http.ServeMux
	templates   *template.Template
	sessions    *model.SessionStore
	scanner     *Scanner
	scanSem     chan struct{} // limits concurrent scans to 1
	configStore *ConfigStore
}

// NewServer creates and configures the web server
func NewServer(scanner *Scanner) *Server {
	s := &Server{
		mux:         http.NewServeMux(),
		sessions:    model.NewSessionStore(),
		scanner:     scanner,
		scanSem:     make(chan struct{}, 1),
		configStore: newConfigStore(),
	}

	s.loadTemplates()
	s.registerRoutes()

	return s
}

func (s *Server) loadTemplates() {
	funcMap := template.FuncMap{
		"resultTypeName": resultTypeName,
		"maskValue":      maskValue,
		"add":            func(a, b int) int { return a + b },
		"sub":            func(a, b int) int { return a - b },
		"groupByFile":    groupByFile,
		"joinLines": func(lines []string) string {
			return strings.Join(lines, "\n")
		},
		"contains": func(slice []string, item string) bool {
			for _, s := range slice {
				if s == item {
					return true
				}
			}
			return false
		},
		"dict": func(pairs ...interface{}) map[string]interface{} {
			m := make(map[string]interface{}, len(pairs)/2)
			for i := 0; i < len(pairs)-1; i += 2 {
				m[pairs[i].(string)] = pairs[i+1]
			}
			return m
		},
		"makeRowData": func(sessionID string, ir model.IndexedResult) model.ResultRowData {
			return model.ResultRowData{SessionID: sessionID, Index: ir.Index, Result: ir.Result}
		},
	}

	s.templates = template.Must(
		template.New("").Funcs(funcMap).ParseFS(templateFS, "templates/*.html", "templates/partials/*.html"),
	)
}

func (s *Server) registerRoutes() {
	// Static files
	staticSub, _ := fs.Sub(staticFS, "static")
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	// Pages
	s.mux.HandleFunc("GET /{$}", s.handleIndex)
	s.mux.HandleFunc("POST /scan", s.handleScan)
	s.mux.HandleFunc("GET /scan/{id}/progress", s.handleProgress)
	s.mux.HandleFunc("GET /scan/{id}/results", s.handleResults)
	s.mux.HandleFunc("DELETE /scan/{id}/dismiss/{index}", s.handleDismiss)
	s.mux.HandleFunc("DELETE /scan/{id}/dismiss-file", s.handleDismissFile)
	s.mux.HandleFunc("DELETE /scan/{id}/dismiss-value", s.handleDismissValue)
	s.mux.HandleFunc("POST /scan/{id}/export", s.handleExportResults)
	s.mux.HandleFunc("POST /import", s.handleImportResults)

	// Config
	s.mux.HandleFunc("GET /config", s.handleConfigGet)
	s.mux.HandleFunc("POST /config", s.handleConfigSave)
	s.mux.HandleFunc("DELETE /config", s.handleConfigDelete)
	s.mux.HandleFunc("POST /config/export", s.handleConfigExport)
}

// ServeHTTP implements http.Handler, applying security headers to every response.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
	s.mux.ServeHTTP(w, r)
}

// --- Template helpers ---

func resultTypeName(t int) string {
	switch t {
	case parser.TypeGoComment:
		return "Go Comment"
	case parser.TypeGoVariable:
		return "Go Variable"
	case parser.TypeGoOther:
		return "Go Other"
	case parser.TypeJSONVariable:
		return "JSON Variable"
	case parser.TypeJSONListVal:
		return "JSON List"
	case parser.TypeYamlVariable:
		return "YAML Variable"
	case parser.TypeYamlListVal:
		return "YAML List"
	case parser.TypeK8sEnvVariable:
		return "K8s Env Variable"
	case parser.TypeK8sSecret:
		return "K8s Secret"
	case parser.TypeK8sFlag:
		return "K8s CLI Flag"
	case parser.TypePropertiesComment:
		return "Properties Comment"
	case parser.TypePropertiesValue:
		return "Properties Value"
	case parser.TypePrivateKey:
		return "Private Key"
	case parser.TypeXMLElement:
		return "XML Element"
	case parser.TypeXMLAttribute:
		return "XML Attribute"
	case parser.TypePHPVariable:
		return "PHP Variable"
	case parser.TypePHPHeredoc:
		return "PHP Heredoc"
	case parser.TypePHPConstant:
		return "PHP Constant"
	case parser.TypePHPComment:
		return "PHP Comment"
	case parser.TypePHPOther:
		return "PHP Other"
	case parser.TypeBashVariable:
		return "Bash Variable"
	case parser.TypeGenericCodeVariable:
		return "Code Variable"
	case parser.TypeGenericCodeComment:
		return "Code Comment"
	case parser.TypeGenericCodeOther:
		return "Code Other"
	case parser.TypeGeneric:
		return "Generic"
	case parser.TypeJSVariable:
		return "JS Variable"
	case parser.TypeJSComment:
		return "JS Comment"
	case parser.TypeJSOther:
		return "JS Other"
	case parser.TypeHTMLScript:
		return "HTML Script"
	default:
		return "Unknown"
	}
}

func maskValue(value string) string {
	if len(value) <= 8 {
		return strings.Repeat("*", len(value))
	}
	return value[:4] + strings.Repeat("*", len(value)-8) + value[len(value)-4:]
}

// FileGroup organizes results by file for template rendering
type FileGroup struct {
	File    string
	Results []model.IndexedResult
}

func groupByFile(results []model.IndexedResult) []FileGroup {
	var groups []FileGroup
	var current *FileGroup

	for _, r := range results {
		if current == nil || current.File != r.Result.File {
			if current != nil {
				groups = append(groups, *current)
			}
			current = &FileGroup{
				File:    r.Result.File,
				Results: []model.IndexedResult{r},
			}
		} else {
			current.Results = append(current.Results, r)
		}
	}
	if current != nil {
		groups = append(groups, *current)
	}

	return groups
}
