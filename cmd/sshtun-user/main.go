package main

import (
	"fmt"
	"os"

	"github.com/net2share/sshtun-user/internal/cli"
)

// Version and BuildTime are set at build time.
var (
	version   = "dev"
	buildTime = "unknown"
)

func main() {
	cli.Version = version
	cli.BuildTime = buildTime

	if err := cli.Run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
