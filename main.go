package main

import (
	"log"

	"github.com/ynori7/credential-detector/config"
	"github.com/ynori7/credential-detector/parser"
	"github.com/ynori7/credential-detector/printer"
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
		printer.DisableColors()
	}

	printer.PrintStatistics(p.Statistics)
	printer.PrintResults(p.Results)
}
