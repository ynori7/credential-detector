package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/ynori7/credential-detector/config"
	"github.com/ynori7/credential-detector/parser"
)

func main() {
	conf, err := config.New()
	if err != nil {
		log.Fatal(err.Error())
	}

	p := parser.NewParser(conf)

	err = filepath.Walk(config.ScanPath,
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
		log.Fatal(err.Error())
	}

	if conf.DisableOutputColors {
		disableColors()
	}
	PrintResults(p.Results)
}
