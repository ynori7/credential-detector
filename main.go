package main

import (
	"log"

	"github.com/ynori7/credential-detector/config"
	"github.com/ynori7/credential-detector/parser"
)

func main() {
	conf, err := config.New()
	if err != nil {
		log.Fatal(err.Error())
	}

	p := parser.NewParser(conf)
	if err := p.Scan(config.ScanPath); err != nil {
		log.Fatal(err.Error())
	}

	if conf.DisableOutputColors {
		disableColors()
	}

	PrintStatistics(p.Statistics)
	PrintResults(p.Results)
}
