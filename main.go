package main

import "github.com/net2share/sshtun-user/cmd"

// Version and BuildTime are set at build time.
var (
	version   = "dev"
	buildTime = "unknown"
)

func main() {
	cmd.SetVersionInfo(version, buildTime)
	cmd.Execute()
}
