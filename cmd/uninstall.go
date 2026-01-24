package cmd

import (
	"fmt"

	"github.com/net2share/go-corelib/osdetect"
	"github.com/net2share/sshtun-user/pkg/sshdconfig"
	"github.com/net2share/sshtun-user/pkg/tunneluser"
	"github.com/spf13/cobra"
)

var uninstallCmd = &cobra.Command{
	Use:   "uninstall [users|all]",
	Short: "Uninstall components",
	Long: `Uninstall sshtun-user components.

Subcommands:
  users    Delete all tunnel users
  all      Complete uninstall (users + configuration)

Examples:
  sshtun-user uninstall users    # Delete all tunnel users
  sshtun-user uninstall all      # Complete uninstall`,
	RunE: runUninstall,
}

func runUninstall(cmd *cobra.Command, args []string) error {
	if err := osdetect.RequireRoot(); err != nil {
		return err
	}

	if len(args) == 0 {
		return cmd.Help()
	}

	switch args[0] {
	case "users":
		return uninstallUsersCLI()
	case "all":
		return uninstallAllCLI()
	default:
		return fmt.Errorf("unknown subcommand: %s", args[0])
	}
}

func uninstallUsersCLI() error {
	users, _ := tunneluser.List()
	if len(users) == 0 {
		fmt.Println("No tunnel users to delete.")
		return nil
	}

	deleted, err := tunneluser.DeleteAllUsers()
	if len(deleted) > 0 {
		fmt.Printf("Deleted users: %v\n", deleted)
	}

	tunneluser.CleanupAuthorizedKeysDir()
	tunneluser.CleanupDenyFiles()

	return err
}

func uninstallAllCLI() error {
	// Delete all users
	users, _ := tunneluser.List()
	if len(users) > 0 {
		fmt.Println("Deleting tunnel users...")
		deleted, err := tunneluser.DeleteAllUsers()
		if len(deleted) > 0 {
			fmt.Printf("Deleted: %v\n", deleted)
		}
		if err != nil {
			fmt.Printf("Warning: %v\n", err)
		}
	}

	// Remove sshd config
	if sshdconfig.IsConfigured() {
		fmt.Println("Removing sshd configuration...")
		if err := sshdconfig.RemoveAndReload(); err != nil {
			fmt.Printf("Warning: %v\n", err)
		}
	}

	// Remove groups
	fmt.Println("Removing tunnel groups...")
	if err := tunneluser.DeleteGroups(); err != nil {
		fmt.Printf("Warning: %v\n", err)
	}

	// Cleanup
	tunneluser.CleanupAuthorizedKeysDir()
	tunneluser.CleanupDenyFiles()

	fmt.Println("Uninstall complete.")
	return nil
}
