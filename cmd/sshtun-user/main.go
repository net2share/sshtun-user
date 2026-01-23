package main

import (
	"fmt"
	"os"

	"github.com/net2share/sshtun-user/internal/cli"
)

// Version is set at build time.
var version = "dev"

func main() {
	cli.Version = version

	if err := cli.Run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
