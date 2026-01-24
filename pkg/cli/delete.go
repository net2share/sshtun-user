package cli

import (
	"fmt"

	"github.com/net2share/go-corelib/tui"
	"github.com/net2share/sshtun-user/pkg/tunneluser"
)

// DeleteUserInteractive handles user deletion in interactive mode.
func DeleteUserInteractive() error {
	fmt.Println()
	users, err := tunneluser.List()
	if err != nil {
		return fmt.Errorf("failed to list users: %w", err)
	}

	if len(users) == 0 {
		tui.PrintInfo("No tunnel users to delete.")
		return nil
	}

	// Show available users
	fmt.Println("Available tunnel users:")
	for _, user := range users {
		fmt.Printf("  - %s (%s)\n", user.Username, user.AuthMode)
	}
	fmt.Println()

	username := tui.Prompt("Enter username to delete (or empty to cancel)")
	if username == "" {
		tui.PrintInfo("Cancelled")
		return nil
	}

	// Verify user is a tunnel user
	if !tunneluser.IsTunnelUser(username) {
		return fmt.Errorf("'%s' is not a tunnel user", username)
	}

	// Confirm deletion
	fmt.Println()
	if !tui.Confirm(fmt.Sprintf("Delete user '%s'?", username), false) {
		tui.PrintInfo("Cancelled")
		return nil
	}

	if err := tunneluser.Delete(username); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	tui.PrintSuccess(fmt.Sprintf("User '%s' deleted successfully!", username))
	return nil
}

// DeleteUserCLI handles user deletion from command line.
func DeleteUserCLI(username string) error {
	if username == "" {
		return fmt.Errorf("username required for delete command")
	}

	if !tunneluser.IsTunnelUser(username) {
		return fmt.Errorf("user '%s' is not a tunnel user", username)
	}

	if err := tunneluser.Delete(username); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	fmt.Printf("User '%s' deleted successfully.\n", username)
	return nil
}
