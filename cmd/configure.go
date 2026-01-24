package cmd

import (
	"fmt"

	"github.com/net2share/go-corelib/osdetect"
	"github.com/net2share/go-corelib/tui"
	"github.com/net2share/sshtun-user/pkg/fail2ban"
	"github.com/net2share/sshtun-user/pkg/sshdconfig"
	"github.com/spf13/cobra"
)

var configureNoFail2ban bool

var configureCmd = &cobra.Command{
	Use:   "configure",
	Short: "Apply sshd hardening configuration",
	RunE:  runConfigure,
}

func init() {
	configureCmd.Flags().BoolVar(&configureNoFail2ban, "no-fail2ban", false, "Skip fail2ban installation")
}

func runConfigure(cmd *cobra.Command, args []string) error {
	if err := osdetect.RequireRoot(); err != nil {
		return err
	}

	osInfo, err := osdetect.Detect()
	if err != nil {
		tui.PrintWarning("Could not detect OS: " + err.Error())
	} else {
		fmt.Printf("Detected OS: %s (package manager: %s)\n", osInfo.ID, osInfo.PackageManager)
	}

	if err := sshdconfig.Configure(); err != nil {
		return err
	}

	if !configureNoFail2ban {
		if err := fail2ban.SetupWithFeedback(osInfo); err != nil {
			tui.PrintWarning("fail2ban setup warning: " + err.Error())
		}
	}

	fmt.Println()
	fmt.Println("Configuration complete!")
	return nil
}
