package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/worker"
)

func main() {
	dataDir := flag.String("data-dir", ".", "private WSHawk data directory")
	flag.Parse()
	server, err := worker.NewServerWithDataDir(os.Stdin, os.Stdout, os.Stderr, *dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "worker initialization failed: %v\n", err)
		os.Exit(1)
	}
	defer server.Close()
	os.Exit(server.Run())
}
