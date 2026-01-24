package cmd

import (
	"fmt"

	"github.com/net2share/go-corelib/osdetect"
	"github.com/net2share/sshtun-user/pkg/sshdconfig"
	"github.com/net2share/sshtun-user/pkg/tunneluser"
	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all tunnel users",
	RunE:  runList,
}

func runList(cmd *cobra.Command, args []string) error {
	if err := osdetect.RequireRoot(); err != nil {
		return err
	}

	if !sshdconfig.IsConfigured() {
		return fmt.Errorf("sshd not configured. Run 'sshtun-user configure' first")
	}

	users, err := tunneluser.List()
	if err != nil {
		return fmt.Errorf("failed to list users: %w", err)
	}

	if len(users) == 0 {
		fmt.Println("No tunnel users found.")
		return nil
	}

	fmt.Println("Tunnel users:")
	for _, user := range users {
		fmt.Printf("  %s (%s)\n", user.Username, user.AuthMode)
	}

	return nil
}
