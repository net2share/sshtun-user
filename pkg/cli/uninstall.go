package cli

import (
	"fmt"

	"github.com/net2share/go-corelib/tui"
	"github.com/net2share/sshtun-user/pkg/sshdconfig"
	"github.com/net2share/sshtun-user/pkg/tunneluser"
)

// UninstallInteractive shows the uninstall submenu.
func UninstallInteractive() error {
	for {
		fmt.Println()
		fmt.Println("Uninstall Options:")
		fmt.Println()
		fmt.Println("  1) Delete all tunnel users")
		fmt.Println("     Removes all users in sshtunnel-password and sshtunnel-key groups")
		fmt.Println()
		fmt.Println("  2) Remove configuration (groups, sshd config, cleanup)")
		fmt.Println("     Removes tunnel groups, sshd hardening config, and cleans up files")
		fmt.Println("     Note: Requires all tunnel users to be deleted first")
		fmt.Println()
		fmt.Println("  3) Complete uninstall (users + configuration)")
		fmt.Println("     Deletes all tunnel users, then removes all configuration")
		fmt.Println()
		fmt.Println("  0) Back")
		fmt.Println()

		choice := tui.Prompt("Select option")

		switch choice {
		case "1":
			if err := UninstallUsers(); err != nil {
				tui.PrintError(err.Error())
			}
			tui.WaitForEnter()
		case "2":
			if err := UninstallConfig(); err != nil {
				tui.PrintError(err.Error())
			}
			tui.WaitForEnter()
		case "3":
			if err := UninstallAll(); err != nil {
				tui.PrintError(err.Error())
			}
			tui.WaitForEnter()
		case "0", "q", "back":
			return nil
		default:
			tui.PrintError("Invalid option")
		}
	}
}

// UninstallUsers deletes all tunnel users.
func UninstallUsers() error {
	users, err := tunneluser.List()
	if err != nil {
		return fmt.Errorf("failed to list users: %w", err)
	}

	if len(users) == 0 {
		tui.PrintInfo("No tunnel users to delete.")
		return nil
	}

	fmt.Println()
	fmt.Println("The following users will be deleted:")
	for _, user := range users {
		fmt.Printf("  - %s (%s)\n", user.Username, user.AuthMode)
	}
	fmt.Println()

	if !tui.Confirm(fmt.Sprintf("Delete all %d tunnel users?", len(users)), false) {
		tui.PrintInfo("Cancelled")
		return nil
	}

	fmt.Println()
	deleted, err := tunneluser.DeleteAllUsers()
	if len(deleted) > 0 {
		fmt.Printf("Deleted users: %v\n", deleted)
	}

	if err != nil {
		return err
	}

	// Clean up authorized_keys.d
	tunneluser.CleanupAuthorizedKeysDir()
	tunneluser.CleanupDenyFiles()

	fmt.Println()
	tui.PrintSuccess("All tunnel users deleted!")
	return nil
}

// UninstallConfig removes configuration (groups, sshd config).
func UninstallConfig() error {
	// Check if there are still users
	hasUsers, _ := tunneluser.GroupsHaveUsers()
	if hasUsers {
		return fmt.Errorf("cannot remove configuration: tunnel users still exist. Delete users first (option 1)")
	}

	fmt.Println()
	fmt.Println("This will remove:")
	fmt.Println("  - Tunnel groups (sshtunnel-password, sshtunnel-key)")
	fmt.Println("  - sshd hardening configuration files")
	fmt.Println("  - Authorized keys directory (if empty)")
	fmt.Println()

	if !tui.Confirm("Remove all configuration?", false) {
		tui.PrintInfo("Cancelled")
		return nil
	}

	fmt.Println()

	// Remove sshd config
	if sshdconfig.IsConfigured() {
		fmt.Println("Removing sshd configuration...")
		if err := sshdconfig.RemoveAndReload(); err != nil {
			tui.PrintWarning("sshd config removal warning: " + err.Error())
		} else {
			fmt.Println("  sshd configuration removed")
		}
	}

	// Remove groups
	fmt.Println("Removing tunnel groups...")
	if err := tunneluser.DeleteGroups(); err != nil {
		tui.PrintWarning("Group removal warning: " + err.Error())
	} else {
		fmt.Println("  Tunnel groups removed")
	}

	// Cleanup authorized_keys.d
	fmt.Println("Cleaning up authorized_keys.d...")
	tunneluser.CleanupAuthorizedKeysDir()

	// Cleanup deny files
	fmt.Println("Cleaning up cron.deny and at.deny...")
	tunneluser.CleanupDenyFiles()

	fmt.Println()
	tui.PrintSuccess("Configuration removed!")
	return nil
}

// UninstallAll performs complete uninstall (users + config).
func UninstallAll() error {
	users, _ := tunneluser.List()

	fmt.Println()
	tui.PrintWarning("This will completely remove sshtun-user configuration:")
	if len(users) > 0 {
		fmt.Printf("  - Delete %d tunnel user(s)\n", len(users))
	}
	fmt.Println("  - Remove tunnel groups")
	fmt.Println("  - Remove sshd hardening configuration")
	fmt.Println("  - Clean up authorized keys and deny files")
	fmt.Println()

	if !tui.Confirm("Proceed with complete uninstall?", false) {
		tui.PrintInfo("Cancelled")
		return nil
	}

	fmt.Println()

	// Delete all users first
	if len(users) > 0 {
		fmt.Println("Deleting tunnel users...")
		deleted, err := tunneluser.DeleteAllUsers()
		if len(deleted) > 0 {
			for _, u := range deleted {
				fmt.Printf("  Deleted: %s\n", u)
			}
		}
		if err != nil {
			tui.PrintWarning("Some users could not be deleted: " + err.Error())
		}
	}

	// Remove sshd config
	if sshdconfig.IsConfigured() {
		fmt.Println("Removing sshd configuration...")
		if err := sshdconfig.RemoveAndReload(); err != nil {
			tui.PrintWarning("sshd config removal warning: " + err.Error())
		} else {
			fmt.Println("  sshd configuration removed")
		}
	}

	// Remove groups
	fmt.Println("Removing tunnel groups...")
	if err := tunneluser.DeleteGroups(); err != nil {
		tui.PrintWarning("Group removal warning: " + err.Error())
	} else {
		fmt.Println("  Tunnel groups removed")
	}

	// Cleanup
	fmt.Println("Cleaning up...")
	tunneluser.CleanupAuthorizedKeysDir()
	tunneluser.CleanupDenyFiles()

	fmt.Println()
	tui.PrintSuccess("Complete uninstall finished!")
	return nil
}

// UninstallAllNonInteractive performs complete uninstall without prompts.
// This is used by dnstm to uninstall SSH tunnel config as part of its uninstall.
func UninstallAllNonInteractive() error {
	// Delete all users
	users, _ := tunneluser.List()
	if len(users) > 0 {
		fmt.Println("Deleting tunnel users...")
		deleted, err := tunneluser.DeleteAllUsers()
		if len(deleted) > 0 {
			for _, u := range deleted {
				fmt.Printf("  Deleted: %s\n", u)
			}
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
		} else {
			fmt.Println("  sshd configuration removed")
		}
	}

	// Remove groups
	fmt.Println("Removing tunnel groups...")
	if err := tunneluser.DeleteGroups(); err != nil {
		fmt.Printf("Warning: %v\n", err)
	} else {
		fmt.Println("  Tunnel groups removed")
	}

	// Cleanup
	fmt.Println("Cleaning up...")
	tunneluser.CleanupAuthorizedKeysDir()
	tunneluser.CleanupDenyFiles()

	return nil
}

// UninstallCLI handles uninstall from CLI.
func UninstallCLI(subcommand string) error {
	switch subcommand {
	case "users":
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

	case "all":
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

	default:
		// No subcommand - show usage
		fmt.Println("Usage: sshtun-user uninstall <subcommand>")
		fmt.Println()
		fmt.Println("Subcommands:")
		fmt.Println("  users    Delete all tunnel users")
		fmt.Println("  all      Complete uninstall (users + configuration)")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  sshtun-user uninstall users    # Delete all tunnel users")
		fmt.Println("  sshtun-user uninstall all      # Complete uninstall")
		return nil
	}
}
