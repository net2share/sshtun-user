package cmd

import (
	"fmt"

	"github.com/net2share/go-corelib/osdetect"
	"github.com/net2share/sshtun-user/pkg/sshdconfig"
	"github.com/net2share/sshtun-user/pkg/tunneluser"
	"github.com/spf13/cobra"
)

var uninstallCmd = &cobra.Command{
	Use:   "uninstall [users|config|all]",
	Short: "Uninstall components",
	Long: `Uninstall sshtun-user components.

Subcommands:
  users    Delete all tunnel users
  config   Remove configuration (groups, sshd config)
  all      Complete uninstall (users + configuration)

Examples:
  sshtun-user uninstall users    # Delete all tunnel users
  sshtun-user uninstall config   # Remove configuration only
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
	case "config":
		return uninstallConfigCLI()
	case "all":
		return uninstallAllCLI()
	default:
		return fmt.Errorf("unknown subcommand: %s", args[0])
	}
}

func uninstallUsersCLI() error {
	users, _ := tunneluser.List()
	if len(users) == 0 {
		return fmt.Errorf("no tunnel users to delete")
	}

	deleted, err := tunneluser.DeleteAllUsers()
	if len(deleted) > 0 {
		fmt.Printf("Deleted users: %v\n", deleted)
	}

	tunneluser.CleanupAuthorizedKeysDir()
	tunneluser.CleanupDenyFiles()

	return err
}

func uninstallConfigCLI() error {
	if !sshdconfig.IsConfigured() {
		return fmt.Errorf("sshd is not configured. Nothing to remove")
	}

	hasUsers, _ := tunneluser.GroupsHaveUsers()
	if hasUsers {
		return fmt.Errorf("cannot remove configuration: tunnel users still exist. Run 'sshtun-user uninstall users' first")
	}

	fmt.Println("Removing sshd configuration...")
	if err := sshdconfig.RemoveAndReload(); err != nil {
		fmt.Printf("Warning: %v\n", err)
	} else {
		fmt.Println("  sshd configuration removed")
	}

	fmt.Println("Removing tunnel groups...")
	if err := tunneluser.DeleteGroups(); err != nil {
		fmt.Printf("Warning: %v\n", err)
	} else {
		fmt.Println("  Tunnel groups removed")
	}

	tunneluser.CleanupAuthorizedKeysDir()
	tunneluser.CleanupDenyFiles()

	fmt.Println("Configuration removed.")
	return nil
}

func uninstallAllCLI() error {
	configured := sshdconfig.IsConfigured()
	users, _ := tunneluser.List()
	hasUsers := len(users) > 0

	if !configured && !hasUsers {
		return fmt.Errorf("nothing to uninstall: no configuration and no tunnel users found")
	}

	// If only config exists (no users), use 'uninstall config' instead
	if configured && !hasUsers {
		return fmt.Errorf("no tunnel users found. Use 'sshtun-user uninstall config' instead")
	}

	// If only users exist (no config), use 'uninstall users' instead
	if !configured && hasUsers {
		return fmt.Errorf("sshd is not configured. Use 'sshtun-user uninstall users' instead")
	}

	// Delete all users
	if hasUsers {
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
	if configured {
		fmt.Println("Removing sshd configuration...")
		if err := sshdconfig.RemoveAndReload(); err != nil {
			fmt.Printf("Warning: %v\n", err)
		} else {
			fmt.Println("  sshd configuration removed")
		}

		fmt.Println("Removing tunnel groups...")
		if err := tunneluser.DeleteGroups(); err != nil {
			fmt.Printf("Warning: %v\n", err)
		} else {
			fmt.Println("  Tunnel groups removed")
		}
	}

	// Cleanup
	tunneluser.CleanupAuthorizedKeysDir()
	tunneluser.CleanupDenyFiles()

	fmt.Println("Uninstall complete.")
	return nil
}
