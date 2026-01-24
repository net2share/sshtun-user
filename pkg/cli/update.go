package cli

import (
	"fmt"

	"github.com/net2share/go-corelib/tui"
	"github.com/net2share/sshtun-user/pkg/sshdconfig"
	"github.com/net2share/sshtun-user/pkg/tunneluser"
)

// UpdateUserInteractive handles user update in interactive mode.
func UpdateUserInteractive() error {
	fmt.Println()
	users, err := tunneluser.List()
	if err != nil {
		return fmt.Errorf("failed to list users: %w", err)
	}

	if len(users) == 0 {
		tui.PrintInfo("No tunnel users to update.")
		return nil
	}

	// Show available users
	fmt.Println("Available tunnel users:")
	for _, user := range users {
		fmt.Printf("  - %s (%s)\n", user.Username, user.AuthMode)
	}
	fmt.Println()

	username := tui.Prompt("Enter username to update (or empty to cancel)")
	if username == "" {
		tui.PrintInfo("Cancelled")
		return nil
	}

	// Verify user is a tunnel user
	if !tunneluser.IsTunnelUser(username) {
		return fmt.Errorf("'%s' is not a tunnel user", username)
	}

	// Get current auth mode
	currentMode, _ := tunneluser.GetAuthMode(username)

	return ShowUpdateUserMenu(username, currentMode)
}

// ShowUpdateUserMenu shows the update menu for a specific user.
func ShowUpdateUserMenu(username string, currentMode tunneluser.AuthMode) error {
	fmt.Println()
	fmt.Printf("Updating user '%s' (current auth: %s)\n", username, currentMode)
	fmt.Println()
	fmt.Println("What would you like to update?")
	fmt.Println("  1) Change password (switch to password auth if needed)")
	fmt.Println("  2) Change SSH key (switch to key auth if needed)")
	fmt.Println("  0) Cancel")
	fmt.Println()

	choice := tui.Prompt("Select option")

	switch choice {
	case "1":
		return UpdateUserPassword(username, currentMode)
	case "2":
		return UpdateUserKey(username, currentMode)
	case "0":
		tui.PrintInfo("Cancelled")
		return nil
	default:
		return fmt.Errorf("invalid option")
	}
}

// UpdateUserPassword updates a user's password and switches to password auth if needed.
func UpdateUserPassword(username string, currentMode tunneluser.AuthMode) error {
	password, err := PromptPassword(username)
	if err != nil {
		return err
	}

	// Set password
	if err := tunneluser.SetPassword(username, password); err != nil {
		return fmt.Errorf("failed to set password: %w", err)
	}

	// Switch to password auth group if not already
	if currentMode != tunneluser.AuthModePassword {
		if err := tunneluser.SwitchAuthMode(username, tunneluser.AuthModePassword); err != nil {
			return fmt.Errorf("failed to switch auth mode: %w", err)
		}
		fmt.Printf("Switched '%s' from %s to password authentication\n", username, currentMode)
	}

	fmt.Println()
	tui.PrintSuccess(fmt.Sprintf("Password updated for '%s'!", username))
	PrintClientUsage(username, tunneluser.AuthModePassword)
	return nil
}

// UpdateUserKey updates a user's SSH key and switches to key auth if needed.
func UpdateUserKey(username string, currentMode tunneluser.AuthMode) error {
	publicKey, err := PromptPubkey(username)
	if err != nil {
		return err
	}

	// Set SSH key
	if err := tunneluser.SetupSSHKey(username, publicKey); err != nil {
		return fmt.Errorf("failed to set SSH key: %w", err)
	}

	// Switch to key auth group if not already
	if currentMode != tunneluser.AuthModeKey {
		if err := tunneluser.SwitchAuthMode(username, tunneluser.AuthModeKey); err != nil {
			return fmt.Errorf("failed to switch auth mode: %w", err)
		}
		fmt.Printf("Switched '%s' from %s to key authentication\n", username, currentMode)
	}

	// Ensure AuthorizedKeysFile directive is present
	if err := sshdconfig.AddAuthorizedKeysDirective(); err != nil {
		tui.PrintWarning("Could not add AuthorizedKeysFile directive: " + err.Error())
	}

	fmt.Println()
	tui.PrintSuccess(fmt.Sprintf("SSH key updated for '%s'!", username))
	PrintClientUsage(username, tunneluser.AuthModeKey)
	return nil
}
