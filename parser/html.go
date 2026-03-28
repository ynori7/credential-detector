package parser

import (
	"os"
	"strings"

	"github.com/ynori7/credential-detector/config"
)

const (
	htmlFileExtension  = ".html"
	xhtmlFileExtension = ".xhtml"
)

func (p *Parser) isParsableHTMLFile(filepath string) bool {
	if _, ok := p.scanTypes[config.ScanTypeHTML]; !ok {
		return false
	}

	_, extension := getFileNameAndExtension(filepath)
	return extension == htmlFileExtension || extension == xhtmlFileExtension
}

func (p *Parser) parseHTMLFile(filepath string) {
	if len(filepath) == 0 {
		return
	}

	file, err := os.Open(filepath)
	if err != nil {
		return
	}
	defer file.Close()

	reader := getReader(file)
	defer putReader(reader)

	lineNumber := 1
	inScript := false
	scriptStartLine := 0
	var scriptLines []string

	var line string

	for {
		line, err = reader.ReadString('\n')

		lineLower := strings.ToLower(line)

		if !inScript {
			// Check if a <script> tag opens on this line
			if idx := findScriptOpen(lineLower); idx >= 0 {
				inScript = true
				scriptStartLine = lineNumber

				// Content may start on the same line after the tag
				closeTagIdx := strings.Index(lineLower[idx:], ">")
				if closeTagIdx >= 0 {
					afterTag := line[idx+closeTagIdx+1:]
					// Check if </script> is also on the same line
					if endIdx := findScriptClose(strings.ToLower(afterTag)); endIdx >= 0 {
						content := afterTag[:endIdx]
						if strings.TrimSpace(content) != "" {
							p.parseJavaScriptContent(filepath, content, scriptStartLine-1)
						}
						inScript = false
					} else {
						if strings.TrimSpace(afterTag) != "" {
							scriptLines = append(scriptLines, afterTag)
						}
					}
				}
			}
		} else {
			// We're inside a <script> block — check for closing tag
			if endIdx := findScriptClose(lineLower); endIdx >= 0 {
				// Add content before the closing tag
				before := line[:endIdx]
				before = strings.TrimRight(before, "\n")
				if strings.TrimSpace(before) != "" {
					scriptLines = append(scriptLines, before)
				}

				content := strings.Join(scriptLines, "\n")
				if strings.TrimSpace(content) != "" {
					p.parseJavaScriptContent(filepath, content, scriptStartLine)
				}

				scriptLines = nil
				inScript = false
			} else {
				scriptLines = append(scriptLines, strings.TrimRight(line, "\n"))
			}
		}

		if err != nil {
			// If we were in a script block, flush remaining content
			if inScript && len(scriptLines) > 0 {
				content := strings.Join(scriptLines, "\n")
				if strings.TrimSpace(content) != "" {
					p.parseJavaScriptContent(filepath, content, scriptStartLine)
				}
			}
			return
		}
		lineNumber++
	}
}

// findScriptOpen finds the start of a <script tag (case-insensitive) and returns its index, or -1.
func findScriptOpen(lineLower string) int {
	idx := strings.Index(lineLower, "<script")
	if idx < 0 {
		return -1
	}
	// Make sure it's actually a tag (followed by > or space/attribute)
	afterScript := lineLower[idx+len("<script"):]
	if len(afterScript) == 0 {
		return idx
	}
	ch := afterScript[0]
	if ch == '>' || ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
		return idx
	}
	return -1
}

// findScriptClose finds the </script> close tag (case-insensitive) and returns its index, or -1.
func findScriptClose(lineLower string) int {
	return strings.Index(lineLower, "</script>")
}
