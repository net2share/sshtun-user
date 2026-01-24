// Package cli provides the public API for sshtun-user.
// This package is imported by dnstm to reuse SSH tunnel user management.
package cli

import (
	"fmt"

	"github.com/charmbracelet/huh"
	"github.com/net2share/go-corelib/osdetect"
	"github.com/net2share/go-corelib/tui"
	"github.com/net2share/sshtun-user/internal/menu"
	"github.com/net2share/sshtun-user/pkg/fail2ban"
	"github.com/net2share/sshtun-user/pkg/sshdconfig"
	"github.com/net2share/sshtun-user/pkg/tunneluser"
)

// Version and BuildTime can be set by the importing package.
var (
	Version   = "dev"
	BuildTime = "unknown"
)

// CreatedUserInfo holds information about a created tunnel user.
type CreatedUserInfo struct {
	Username string
	AuthMode string
	Password string // Only set if password auth and auto-generated
}

// ShowUserManagementMenu shows the user management menu.
// This is called by dnstm.
func ShowUserManagementMenu() {
	menu.RunEmbedded()
}

// ConfigureAndCreateUser auto-configures sshd hardening and prompts for user creation.
// Used by dnstm during SSH mode installation - no confirmation for configuration.
// Returns user info if a user was created, nil otherwise.
func ConfigureAndCreateUser() *CreatedUserInfo {
	fmt.Println()
	tui.PrintInfo("Applying sshd hardening configuration...")

	if err := sshdconfig.Configure(); err != nil {
		tui.PrintError("Failed to configure sshd: " + err.Error())
		return nil
	}
	tui.PrintStatus("sshd hardening applied")

	// Configure fail2ban
	osInfo, _ := osdetect.Detect()
	if err := fail2ban.SetupWithFeedback(osInfo); err != nil {
		tui.PrintWarning("fail2ban setup warning: " + err.Error())
	}

	// Create tunnel user
	fmt.Println()
	userInfo, err := createUserWithInfo()
	if err != nil {
		tui.PrintError(err.Error())
		return nil
	}

	return userInfo
}

// createUserWithInfo creates a user and returns their info for display.
func createUserWithInfo() (*CreatedUserInfo, error) {
	var username string
	err := huh.NewInput().
		Title("Username").
		Description("Enter username for tunnel user").
		Value(&username).
		Validate(func(s string) error {
			if s == "" {
				return fmt.Errorf("username required")
			}
			if tunneluser.Exists(s) {
				return fmt.Errorf("user '%s' already exists", s)
			}
			return nil
		}).
		Run()
	if err != nil {
		return nil, err
	}

	var authMode string
	err = huh.NewSelect[string]().
		Title("Authentication Method").
		Options(
			huh.NewOption("Password - simpler, suitable for shared access", "password"),
			huh.NewOption("SSH Key - more secure, user provides public key", "key"),
		).
		Value(&authMode).
		Run()
	if err != nil {
		return nil, err
	}

	cfg := &tunneluser.Config{
		Username: username,
	}

	userInfo := &CreatedUserInfo{
		Username: username,
		AuthMode: authMode,
	}

	if authMode == "key" {
		cfg.AuthMode = tunneluser.AuthModeKey
		var key string
		err = huh.NewInput().
			Title("SSH Public Key").
			Description(fmt.Sprintf("Enter public key for '%s' (from ~/.ssh/id_ed25519.pub)", username)).
			Value(&key).
			Validate(func(s string) error {
				if s == "" {
					return fmt.Errorf("public key is required for key-based auth")
				}
				if err := tunneluser.ValidatePublicKey(s); err != nil {
					return fmt.Errorf("invalid public key format: %w", err)
				}
				return nil
			}).
			Run()
		if err != nil {
			return nil, err
		}
		cfg.PublicKey = key
	} else {
		cfg.AuthMode = tunneluser.AuthModePassword
		var password string
		err = huh.NewInput().
			Title("Password").
			Description(fmt.Sprintf("Enter password for '%s' (leave empty to auto-generate)", username)).
			Value(&password).
			Run()
		if err != nil {
			return nil, err
		}

		if password == "" {
			generated, err := tunneluser.GeneratePassword()
			if err != nil {
				return nil, fmt.Errorf("failed to generate password: %w", err)
			}
			password = generated
			tui.PrintBox("Generated Password (save this now!)", []string{tui.Code(password)})
		}
		cfg.Password = password
		userInfo.Password = password // Store for display (both entered and generated)
	}

	if err := tunneluser.Create(cfg); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	if cfg.AuthMode == tunneluser.AuthModeKey {
		if err := sshdconfig.AddAuthorizedKeysDirective(); err != nil {
			tui.PrintWarning("Could not add AuthorizedKeysFile directive: " + err.Error())
		}
	}

	fmt.Println()
	tui.PrintSuccess(fmt.Sprintf("User '%s' created successfully!", username))

	return userInfo, nil
}

// IsConfigured checks if sshd hardening has been applied.
func IsConfigured() bool {
	return sshdconfig.IsConfigured()
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
