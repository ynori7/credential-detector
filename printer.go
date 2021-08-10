package main

import (
	"fmt"
	"runtime"
	"sort"

	"github.com/ynori7/credential-detector/parser"
)

var (
	fgYellow = "\033[33m"
	bgRed    = "\u001b[41m"
	reset    = "\033[0m"
)

func init() {
	if runtime.GOOS == "windows" {
		disableColors()
	}
}

// PrintResults outputs the results of the credential scan
func PrintResults(results []parser.Result) {
	// sort the results by file and then by line
	sort.Slice(results, func(i, j int) bool {
		if results[i].File == results[j].File {
			if results[i].Line == results[j].Line {
				return results[i].Name < results[j].Name
			}
			return results[i].Line < results[j].Line
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
			fmt.Printf("\n%sIn %s%s\n\n", bgRed, currentFile, reset)
		}

		switch result.Type {
		case parser.TypeGoVariable:
			printGoVariableResult(result)
		case parser.TypeGoComment:
			printGoCommentResult(result)
		case parser.TypeJSONVariable:
			printJSONVariableResult(result)
		case parser.TypeJSONListVal:
			printJSONListValResult(result)
		case parser.TypeYamlVariable:
			printYamlVariableResult(result)
		case parser.TypeYamlListVal:
			printYamlListValResult(result)
		case parser.TypePropertiesValue:
			printPropertiesValueResult(result)
		case parser.TypePropertiesComment:
			printPropertiesCommentResult(result)
		}
	}
}

func printGoVariableResult(result parser.Result) {
	fmt.Printf(`%sLine %d:%s 
%s = %s

`, fgYellow, result.Line, reset, result.Name, result.Value)
}

func printGoCommentResult(result parser.Result) {
	fmt.Printf(`%sLine %d:%s 
%s

`, fgYellow, result.Line, reset, result.Value)
}

func printJSONVariableResult(result parser.Result) {
	fmt.Printf(`%sJSON Variable:%s 
"%s": "%s"

`, fgYellow, reset, result.Name, result.Value)
}

func printJSONListValResult(result parser.Result) {
	fmt.Printf(`%sJSON List Item:%s
"%s": [
...
"%s",
...
]

`, fgYellow, reset, result.Name, result.Value)
}

func printYamlVariableResult(result parser.Result) {
	fmt.Printf(`%sYAML Variable:%s 
"%s": "%s"

`, fgYellow, reset, result.Name, result.Value)
}

func printYamlListValResult(result parser.Result) {
	fmt.Printf(`%sYAML List Item:%s
"%s": [
...
- "%s",
...
]

`, fgYellow, reset, result.Name, result.Value)
}

func printPropertiesValueResult(result parser.Result) {
	fmt.Printf(`%sLine %d:%s 
%s=%s

`, fgYellow, result.Line, reset, result.Name, result.Value)
}

func printPropertiesCommentResult(result parser.Result) {
	fmt.Printf(`%sLine %d:%s 
%s

`, fgYellow, result.Line, reset, result.Value)
}

func disableColors() {
	fgYellow = ""
	bgRed = ""
	reset = ""
}
