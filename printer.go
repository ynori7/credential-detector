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

// PrintStatistics outputs the statistics related to the credential scan
func PrintStatistics(stats parser.Statistics) {
	fmt.Printf("Files found: %d\n", stats.FilesFound)
	fmt.Printf("Files scanned: %d\n", stats.FilesScanned)
	fmt.Printf("Results found: %d\n\n", stats.ResultsFound)
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
			printGoOtherResult(result)
		case parser.TypeGoOther:
			printGoOtherResult(result)
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
		case parser.TypePrivateKey:
			printPrivateKeyResult(result)
		case parser.TypeXMLElement:
			printXMLElementResult(result)
		case parser.TypeXMLAttribute:
			printXMLAttributeResult(result)
		case parser.TypePHPVariable, parser.TypePHPHeredoc, parser.TypePHPConstant:
			printPhpVariableResult(result)
		case parser.TypePHPComment:
			printPhpOtherResult(result)
		case parser.TypePHPOther:
			printPhpOtherResult(result)
		case parser.TypeGeneric:
			printGenericResult(result)
		case parser.TypeGenericCode:
			printGenericCodeVariableResult(result)
		}
	}
}

func printGoVariableResult(result parser.Result) {
	fmt.Printf(`%sLine %d:%s 
%s = %s

`, fgYellow, result.Line, reset, result.Name, result.Value)
}

func printGoOtherResult(result parser.Result) {
	fmt.Printf(`%sLine %d:%s 
Possible %s
%s

`, fgYellow, result.Line, reset, result.CredentialType, result.Value)
}

func printJSONVariableResult(result parser.Result) {
	fmt.Printf(`%sJSON Variable:%s 
"%s": "%s"

`, fgYellow, reset, result.Name, result.Value)
}

func printJSONListValResult(result parser.Result) {
	fmt.Printf(`%sJSON List Item:%s
Possible %s
"%s": [
...
"%s",
...
]

`, fgYellow, reset, result.Name, result.CredentialType, result.Value)
}

func printYamlVariableResult(result parser.Result) {
	fmt.Printf(`%sYAML Variable:%s 
"%s": "%s"

`, fgYellow, reset, result.Name, result.Value)
}

func printYamlListValResult(result parser.Result) {
	fmt.Printf(`%sYAML List Item:%s
Possible %s
"%s": [
...
- "%s",
...
]

`, fgYellow, reset, result.Name, result.CredentialType, result.Value)
}

func printPropertiesValueResult(result parser.Result) {
	fmt.Printf(`%sLine %d:%s 
%s=%s

`, fgYellow, result.Line, reset, result.Name, result.Value)
}

func printPropertiesCommentResult(result parser.Result) {
	fmt.Printf(`%sLine %d:%s 
Possible %s
%s

`, fgYellow, result.Line, reset, result.CredentialType, result.Value)
}

func printPrivateKeyResult(result parser.Result) {
	fmt.Printf(`%sPrivate key file:%s 
%s

`, fgYellow, reset, result.Value)
}

func printXMLElementResult(result parser.Result) {
	fmt.Printf(`%sXML Element:%s 
%s = %s

`, fgYellow, reset, result.Name, result.Value)
}

func printXMLAttributeResult(result parser.Result) {
	fmt.Printf(`%sXML Attribute:%s 
%s

`, fgYellow, reset, result.Value)
}

func printPhpVariableResult(result parser.Result) {
	fmt.Printf(`%sLine %d:%s 
%s = %s;

`, fgYellow, result.Line, reset, result.Name, result.Value)
}

func printPhpOtherResult(result parser.Result) {
	fmt.Printf(`%sLine %d:%s
Possible %s
%s

`, fgYellow, result.Line, reset, result.CredentialType, result.Value)
}

func printGenericResult(result parser.Result) {
	fmt.Printf(`%sLine %d:%s
Possible %s
%s

`, fgYellow, result.Line, reset, result.CredentialType, result.Value)
}

func printGenericCodeVariableResult(result parser.Result) {
	fmt.Printf(`%sLine %d:%s 
%s

`, fgYellow, result.Line, reset, result.Value)
}

func disableColors() {
	fgYellow = ""
	bgRed = ""
	reset = ""
}
