package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"

	"github.com/ynori7/credential-detector/config"
	"github.com/ynori7/credential-detector/parser"
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

	conf, err := config.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("Error loading configuration: %s", err.Error())
	}

	p := parser.NewParser(conf)

	err = filepath.Walk(scanPath,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if conf.ExcludeTests && conf.IsTestDirectory(info.Name()) {
				//skip test directories if we're excluding tests
				return filepath.SkipDir
			}
			p.ParseFile(path)
			return nil
		})
	if err != nil {
		log.Println(err)
	}

	if conf.DisableOutputColors {
		disableColors()
	}
	PrintResults(p.Results)
}
