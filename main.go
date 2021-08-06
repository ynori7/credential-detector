package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
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

	for file, results := range parser.Results {
		fmt.Printf("In %s\n\n", file)

		for _, res := range results {
			fmt.Printf("Line %d: %s = %s\n", res.Line, res.Name, res.Value)
		}

		fmt.Printf("\n\n")
	}
}
