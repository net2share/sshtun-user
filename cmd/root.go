// Package cmd provides the Cobra CLI for sshtun-user.
package cmd

import (
	"os"

	"github.com/net2share/go-corelib/osdetect"
	"github.com/net2share/sshtun-user/internal/menu"
	"github.com/spf13/cobra"
)

// Version and BuildTime are set at build time.
var (
	Version   = "dev"
	BuildTime = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "sshtun-user",
	Short: "SSH Tunnel User Manager",
	Long:  "SSH Tunnel User Setup - https://github.com/net2share/sshtun-user",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := osdetect.RequireRoot(); err != nil {
			return err
		}
		menu.Version = Version
		menu.BuildTime = BuildTime
		return menu.Run()
	},
}

func init() {
	rootCmd.Version = Version

	rootCmd.AddCommand(createCmd)
	rootCmd.AddCommand(updateCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(deleteCmd)
	rootCmd.AddCommand(configureCmd)
	rootCmd.AddCommand(uninstallCmd)
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// SetVersionInfo sets version information for the CLI.
func SetVersionInfo(version, buildTime string) {
	Version = version
	BuildTime = buildTime
	rootCmd.Version = version + " (built " + buildTime + ")"
}
