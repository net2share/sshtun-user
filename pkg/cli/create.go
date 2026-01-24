package cli

import (
	"fmt"

	"github.com/net2share/go-corelib/osdetect"
	"github.com/net2share/go-corelib/tui"
	"github.com/net2share/sshtun-user/pkg/fail2ban"
	"github.com/net2share/sshtun-user/pkg/sshdconfig"
	"github.com/net2share/sshtun-user/pkg/tunneluser"
)

// CreateUserInteractive handles user creation in interactive mode.
func CreateUserInteractive(osInfo *osdetect.OSInfo) error {
	fmt.Println()
	username, err := PromptUsername()
	if err != nil {
		return err
	}

	// Check if user already exists
	if tunneluser.Exists(username) {
		return fmt.Errorf("user '%s' already exists. Use 'Update tunnel user' to modify", username)
	}

	// Interactive mode - prompt for auth mode
	cfg := &tunneluser.Config{
		Username: username,
	}

	var promptErr error
	cfg.AuthMode, cfg.Password, cfg.PublicKey, _, promptErr = PromptInteractive(username, false, fail2ban.IsInstalled())
	if promptErr != nil {
		return promptErr
	}

	// Create user
	if err := tunneluser.Create(cfg); err != nil {
		return err
	}

	// Add AuthorizedKeysFile directive if using key auth
	if cfg.AuthMode == tunneluser.AuthModeKey {
		if err := sshdconfig.AddAuthorizedKeysDirective(); err != nil {
			tui.PrintWarning("Could not add AuthorizedKeysFile directive: " + err.Error())
		}
	}

	// Print client usage
	PrintClientUsage(username, cfg.AuthMode)
	fmt.Println()
	tui.PrintSuccess(fmt.Sprintf("User '%s' created successfully!", username))

	return nil
}

// CreateUserSimple handles simple user creation for the user management submenu.
// This is a simplified version without fail2ban prompts.
func CreateUserSimple() error {
	fmt.Println()
	username := tui.Prompt("Enter username for tunnel user")
	if username == "" {
		return fmt.Errorf("username required")
	}

	// Check if user already exists
	if tunneluser.Exists(username) {
		return fmt.Errorf("user '%s' already exists. Use 'Update tunnel user' to modify", username)
	}

	// Prompt for auth mode
	authMode := PromptAuthMode()

	cfg := &tunneluser.Config{
		Username: username,
		AuthMode: authMode,
	}

	var err error
	if authMode == tunneluser.AuthModeKey {
		cfg.PublicKey, err = PromptPubkey(username)
		if err != nil {
			return err
		}
	} else {
		cfg.Password, err = PromptPassword(username)
		if err != nil {
			return err
		}
	}

	// Create the user
	if err := tunneluser.Create(cfg); err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	// Add AuthorizedKeysFile directive if using key auth
	if cfg.AuthMode == tunneluser.AuthModeKey {
		if err := sshdconfig.AddAuthorizedKeysDirective(); err != nil {
			tui.PrintWarning("Could not add AuthorizedKeysFile directive: " + err.Error())
		}
	}

	fmt.Println()
	tui.PrintSuccess(fmt.Sprintf("User '%s' created successfully!", username))
	PrintClientUsage(username, authMode)

	return nil
}

// PrintClientUsage prints SSH client usage examples.
func PrintClientUsage(username string, authMode tunneluser.AuthMode) {
	fmt.Println()
	fmt.Println("Client usage:")
	if authMode == tunneluser.AuthModeKey {
		fmt.Printf("  ssh -D 1080 -N -i <private_key> %s@<server>    # SOCKS proxy\n", username)
		fmt.Printf("  ssh -L 8080:target:80 -N -i <private_key> %s@<server>  # Local forward\n", username)
	} else {
		fmt.Printf("  ssh -D 1080 -N %s@<server>    # SOCKS proxy\n", username)
		fmt.Printf("  ssh -L 8080:target:80 -N %s@<server>  # Local forward\n", username)
	}
}
