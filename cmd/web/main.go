package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/ynori7/credential-detector/web"
)

func main() {
	var (
		port           int
		configPath     string
		rootConfigPath string
	)

	flag.IntVar(&port, "port", 8080, "Port to listen on")
	flag.StringVar(&configPath, "config", "", "Path to config yaml with additions/overrides")
	flag.StringVar(&rootConfigPath, "root_config", "", "Path to root config yaml")
	flag.Parse()

	scanner := web.NewScanner(configPath, rootConfigPath)
	server := web.NewServer(scanner)

	addr := fmt.Sprintf("127.0.0.1:%d", port)

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		fmt.Println("\nShutting down...")
		os.Exit(0)
	}()

	log.Printf("Credential Detector Web UI running at http://%s", addr)
	if err := http.ListenAndServe(addr, server); err != nil {
		log.Fatal(err)
	}
}
