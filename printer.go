package main

import (
	"fmt"
	"runtime"
	"sort"
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

func PrintResults(results []Result) {
	// sort the results by file and then by line
	sort.Slice(results, func(i, j int) bool {
		if results[i].File == results[j].File {
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
			fmt.Printf("\n%sIn %s%s\n\n", BgRed, currentFile, Reset)
		}

		switch result.Type {
		case TypeVariable:
			printVariableResult(result)
		case TypeComment:
			printCommentResult(result)
		}
	}
}

func printVariableResult(result Result) {
	fmt.Printf(`%sLine %d:%s 
%s = %s

`, FgYellow, result.Line, Reset, result.Name, result.Value)
}

func printCommentResult(result Result) {
	fmt.Printf(`%sLine %d:%s 
%s

`, FgYellow, result.Line, Reset, result.Value)
}

func disableColors() {
	FgYellow = ""
	BgRed = ""
	Reset  = ""
}