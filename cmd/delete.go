package cmd

import (
	"fmt"

	"github.com/net2share/go-corelib/osdetect"
	"github.com/net2share/sshtun-user/pkg/sshdconfig"
	"github.com/net2share/sshtun-user/pkg/tunneluser"
	"github.com/spf13/cobra"
)

var deleteCmd = &cobra.Command{
	Use:   "delete <username>",
	Short: "Delete a tunnel user",
	Args:  cobra.ExactArgs(1),
	RunE:  runDelete,
}

func runDelete(cmd *cobra.Command, args []string) error {
	if err := osdetect.RequireRoot(); err != nil {
		return err
	}

	if !sshdconfig.IsConfigured() {
		return fmt.Errorf("sshd not configured. Run 'sshtun-user configure' first")
	}

	username := args[0]

	if !tunneluser.IsTunnelUser(username) {
		return fmt.Errorf("user '%s' is not a tunnel user", username)
	}

	if err := tunneluser.Delete(username); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	fmt.Printf("User '%s' deleted successfully.\n", username)
	return nil
}
