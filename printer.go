package main

import (
	"fmt"
	"runtime"
	"sort"

	"github.com/ynori7/credential-detector/parser"
)

var (
	FgYellow = "\033[33m"
	BgRed    = "\u001b[41m"
	Reset    = "\033[0m"
)

func init() {
	if runtime.GOOS == "windows" {
		disableColors()
	}
}

func PrintResults(results []parser.Result) {
	// sort the results by file and then by line
	sort.Slice(results, func(i, j int) bool {
		if results[i].File == results[j].File {
			if results[i].Line == results[j].Line {
				return results[i].Name < results[j].Name
			} else {
				return results[i].Line < results[j].Line
			}
		}
		return results[i].File < results[j].File
	})

	// output the results
	currentFile := ""
	for _, result := range results {
		if result.File != currentFile {
			if currentFile != "" {
				fmt.Printf("\n\n")
			}
			currentFile = result.File
			fmt.Printf("\n%sIn %s%s\n\n", BgRed, currentFile, Reset)
		}

		switch result.Type {
		case parser.TypeGoVariable:
			printGoVariableResult(result)
		case parser.TypeGoComment:
			printGoCommentResult(result)
		case parser.TypeJsonVariable:
			printJsonVariableResult(result)
		case parser.TypeJsonListVal:
			printJsonListValResult(result)
		case parser.TypeYamlVariable:
			printYamlVariableResult(result)
		case parser.TypeYamlListVal:
			printYamlListValResult(result)
		}
	}
}

func printGoVariableResult(result parser.Result) {
	fmt.Printf(`%sLine %d:%s 
%s = %s

`, FgYellow, result.Line, Reset, result.Name, result.Value)
}

func printGoCommentResult(result parser.Result) {
	fmt.Printf(`%sLine %d:%s 
%s

`, FgYellow, result.Line, Reset, result.Value)
}

func printJsonVariableResult(result parser.Result) {
	fmt.Printf(`%sJSON Variable:%s 
"%s": "%s"

`, FgYellow, Reset, result.Name, result.Value)
}

func printJsonListValResult(result parser.Result) {
	fmt.Printf(`%sJSON List Item:%s
"%s": [
...
"%s",
...
]

`, FgYellow, Reset, result.Name, result.Value)
}

func printYamlVariableResult(result parser.Result) {
	fmt.Printf(`%sYAML Variable:%s 
"%s": "%s"

`, FgYellow, Reset, result.Name, result.Value)
}

func printYamlListValResult(result parser.Result) {
	fmt.Printf(`%sYAML List Item:%s
"%s": [
...
- "%s",
...
]

`, FgYellow, Reset, result.Name, result.Value)
}

func disableColors() {
	FgYellow = ""
	BgRed = ""
	Reset  = ""
}