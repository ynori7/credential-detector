package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
)

func main() {
	var (
		configPath string
		scanPath   string
	)

	flag.StringVar(&configPath, "config", "", "The path to the config yaml")
	flag.StringVar(&scanPath, "path", "", "The path to scan")
	flag.Parse()

	if scanPath == "" {
		log.Fatal("The path flag must be provided")
	}

	conf, err := LoadConfig(configPath)
	if err != nil {
		log.Fatalf("Error loading configuration: %s", err.Error())
	}

	parser := NewParser(conf)

	err = filepath.Walk(scanPath,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			parser.ParseFile(path)
			return nil
		})
	if err != nil {
		log.Println(err)
	}

	results := parser.Results
	sort.Slice(results, func(i, j int) bool {
		if results[i].File == results[j].File {
			return results[i].Line < results[j].Line
		}
		return results[i].File < results[j].File
	})

	currentFile := ""
	for _, result := range parser.Results {
		if result.File != currentFile {
			if currentFile != "" {
				fmt.Printf("\n\n")
			}
			currentFile = result.File
			fmt.Printf("In %s\n\n", currentFile)
		}

		fmt.Printf("Line %d: %s = %s\n", result.Line, result.Name, result.Value)
	}
}
