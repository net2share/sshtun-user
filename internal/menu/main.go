// Package menu provides the interactive menu for sshtun-user.
package menu

import (
	"errors"
	"fmt"

	"github.com/net2share/go-corelib/osdetect"
	"github.com/net2share/go-corelib/tui"
	"github.com/net2share/sshtun-user/pkg/fail2ban"
	"github.com/net2share/sshtun-user/pkg/sshdconfig"
	"github.com/net2share/sshtun-user/pkg/tunneluser"
)

// ErrCancelled is returned when user cancels an operation.
// In menu context, this skips WaitForEnter. In CLI context, this can be handled as an error.
var ErrCancelled = errors.New("cancelled")

// Version and BuildTime are set by cmd package.
var (
	Version   = "dev"
	BuildTime = "unknown"
)

// Run shows the main interactive menu.
func Run() error {
	tui.SetAppInfo("sshtun-user", Version, BuildTime)

	osInfo, err := osdetect.Detect()
	if err != nil {
		tui.PrintWarning("Could not detect OS: " + err.Error())
	} else {
		fmt.Printf("Detected OS: %s (package manager: %s)\n", osInfo.ID, osInfo.PackageManager)
	}

	return runMenuLoop(osInfo)
}

func runMenuLoop(osInfo *osdetect.OSInfo) error {
	for {
		fmt.Println()
		configured := sshdconfig.IsConfigured()
		hasUsers, _ := tunneluser.GroupsHaveUsers()

		options := buildMenuOptions(configured, hasUsers)
		choice, err := tui.RunMenu(tui.MenuConfig{
			Title:   "SSH Tunnel User Manager",
			Options: options,
		})
		if err != nil {
			return err
		}

		if choice == "" || choice == "exit" {
			tui.PrintInfo("Goodbye!")
			return nil
		}

		err = handleChoice(choice, osInfo)
		if errors.Is(err, ErrCancelled) {
			continue
		}
		if err != nil {
			tui.PrintError(err.Error())
		}
		tui.WaitForEnter()
	}
}

func buildMenuOptions(configured, hasUsers bool) []tui.MenuOption {
	var options []tui.MenuOption

	// Configure - only show when NOT configured
	if !configured {
		options = append(options, tui.MenuOption{Label: "Configure sshd hardening", Value: "configure"})
	}

	// User management - only show when configured
	if configured {
		options = append(options,
			tui.MenuOption{Label: "Create tunnel user", Value: "create"},
			tui.MenuOption{Label: "Update tunnel user", Value: "update"},
			tui.MenuOption{Label: "List tunnel users", Value: "list"},
			tui.MenuOption{Label: "Delete tunnel user", Value: "delete"},
		)
	}

	// Uninstall - only show when configured OR users exist
	if configured || hasUsers {
		options = append(options, tui.MenuOption{Label: "Uninstall", Value: "uninstall"})
	}

	options = append(options, tui.MenuOption{Label: "Exit", Value: "exit"})

	return options
}

func handleChoice(choice string, osInfo *osdetect.OSInfo) error {
	switch choice {
	case "create":
		return createUserInteractive()
	case "update":
		return updateUserInteractive()
	case "list":
		return listUsersFullscreen()
	case "delete":
		return deleteUserInteractive()
	case "configure":
		return configureInteractive(osInfo)
	case "uninstall":
		return uninstallInteractive()
	}
	return nil
}

func createUserInteractive() error {
	var username string
	for {
		value, ok, err := tui.RunInput(tui.InputConfig{
			Title:       "Username",
			Description: "Enter username for tunnel user",
		})
		if err != nil {
			return err
		}
		if !ok || value == "" {
			return ErrCancelled
		}

		if tunneluser.Exists(value) {
			tui.PrintError(fmt.Sprintf("user '%s' already exists", value))
			continue
		}
		username = value
		break
	}

	authMode, err := tui.RunMenu(tui.MenuConfig{
		Title: "Authentication Method",
		Options: []tui.MenuOption{
			{Label: "Password - simpler, suitable for shared access", Value: "password"},
			{Label: "SSH Key - more secure, user provides public key", Value: "key"},
		},
	})
	if err != nil {
		return err
	}
	if authMode == "" {
		return ErrCancelled
	}

	cfg := &tunneluser.Config{
		Username: username,
	}

	if authMode == "key" {
		cfg.AuthMode = tunneluser.AuthModeKey
		publicKey, err := PromptPubkey(username)
		if err != nil {
			return err
		}
		cfg.PublicKey = publicKey
	} else {
		cfg.AuthMode = tunneluser.AuthModePassword
		password, err := PromptPassword(username)
		if err != nil {
			return err
		}
		cfg.Password = password
	}

	if err := tunneluser.Create(cfg); err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	if cfg.AuthMode == tunneluser.AuthModeKey {
		if err := sshdconfig.AddAuthorizedKeysDirective(); err != nil {
			tui.PrintWarning("Could not add AuthorizedKeysFile directive: " + err.Error())
		}
	}

	fmt.Println()
	tui.PrintSuccess(fmt.Sprintf("User '%s' created successfully!", username))
	PrintClientUsage(username, cfg.AuthMode)
	return nil
}

func updateUserInteractive() error {
	users, err := tunneluser.List()
	if err != nil {
		return fmt.Errorf("failed to list users: %w", err)
	}

	if len(users) == 0 {
		tui.PrintInfo("No tunnel users to update.")
		return nil
	}

	options := []tui.MenuOption{
		{Label: "Back", Value: ""},
	}
	for _, user := range users {
		label := fmt.Sprintf("%s (%s)", user.Username, user.AuthMode)
		options = append(options, tui.MenuOption{Label: label, Value: user.Username})
	}

	username, err := tui.RunMenu(tui.MenuConfig{
		Title:   "Select user to update",
		Options: options,
	})
	if err != nil {
		return err
	}

	if username == "" {
		return ErrCancelled
	}

	currentMode, _ := tunneluser.GetAuthMode(username)
	return showUpdateUserMenu(username, currentMode)
}

func showUpdateUserMenu(username string, currentMode tunneluser.AuthMode) error {
	fmt.Printf("\nUpdating user '%s' (current auth: %s)\n", username, currentMode)

	choice, err := tui.RunMenu(tui.MenuConfig{
		Title: "What would you like to update?",
		Options: []tui.MenuOption{
			{Label: "Back", Value: "back"},
			{Label: "Change password (switch to password auth if needed)", Value: "password"},
			{Label: "Change SSH key (switch to key auth if needed)", Value: "key"},
		},
	})
	if err != nil {
		return err
	}

	switch choice {
	case "password":
		return updateUserPassword(username, currentMode)
	case "key":
		return updateUserKey(username, currentMode)
	default:
		return ErrCancelled
	}
}

func updateUserPassword(username string, currentMode tunneluser.AuthMode) error {
	password, err := PromptPassword(username)
	if err != nil {
		return err
	}

	if err := tunneluser.SetPassword(username, password); err != nil {
		return fmt.Errorf("failed to set password: %w", err)
	}

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

func updateUserKey(username string, currentMode tunneluser.AuthMode) error {
	publicKey, err := PromptPubkey(username)
	if err != nil {
		return err
	}

	if err := tunneluser.SetupSSHKey(username, publicKey); err != nil {
		return fmt.Errorf("failed to set SSH key: %w", err)
	}

	if currentMode != tunneluser.AuthModeKey {
		if err := tunneluser.SwitchAuthMode(username, tunneluser.AuthModeKey); err != nil {
			return fmt.Errorf("failed to switch auth mode: %w", err)
		}
		fmt.Printf("Switched '%s' from %s to key authentication\n", username, currentMode)
	}

	if err := sshdconfig.AddAuthorizedKeysDirective(); err != nil {
		tui.PrintWarning("Could not add AuthorizedKeysFile directive: " + err.Error())
	}

	fmt.Println()
	tui.PrintSuccess(fmt.Sprintf("SSH key updated for '%s'!", username))
	PrintClientUsage(username, tunneluser.AuthModeKey)
	return nil
}

func listUsersFullscreen() error {
	users, err := tunneluser.List()
	if err != nil {
		return fmt.Errorf("failed to list users: %w", err)
	}

	items := make([]string, len(users))
	for i, user := range users {
		items[i] = fmt.Sprintf("%s (%s auth)", user.Username, user.AuthMode)
	}

	if err := tui.ShowList(tui.ListConfig{
		Title:     "Tunnel Users",
		Items:     items,
		EmptyText: "No tunnel users found.",
	}); err != nil {
		return err
	}

	return ErrCancelled
}

func deleteUserInteractive() error {
	users, err := tunneluser.List()
	if err != nil {
		return fmt.Errorf("failed to list users: %w", err)
	}

	if len(users) == 0 {
		tui.PrintInfo("No tunnel users to delete.")
		return nil
	}

	options := []tui.MenuOption{
		{Label: "Back", Value: ""},
	}
	for _, user := range users {
		label := fmt.Sprintf("%s (%s)", user.Username, user.AuthMode)
		options = append(options, tui.MenuOption{Label: label, Value: user.Username})
	}

	username, err := tui.RunMenu(tui.MenuConfig{
		Title:   "Select user to delete",
		Options: options,
	})
	if err != nil {
		return err
	}

	if username == "" {
		return ErrCancelled
	}

	confirm, err := tui.RunConfirm(tui.ConfirmConfig{
		Title: fmt.Sprintf("Delete user '%s'?", username),
	})
	if err != nil {
		return err
	}

	if !confirm {
		return ErrCancelled
	}

	if err := tunneluser.Delete(username); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	tui.PrintSuccess(fmt.Sprintf("User '%s' deleted successfully!", username))
	return nil
}

func configureInteractive(osInfo *osdetect.OSInfo) error {
	fmt.Println()
	tui.PrintInfo("Applying sshd hardening configuration...")

	if err := sshdconfig.Configure(); err != nil {
		return err
	}

	if !fail2ban.IsInstalled() {
		enableFail2ban, err := tui.RunConfirm(tui.ConfirmConfig{
			Title:       "Enable fail2ban brute-force protection?",
			Description: "Bans IPs after 5 failed login attempts",
		})
		if err != nil {
			return err
		}

		if enableFail2ban {
			if err := fail2ban.SetupWithFeedback(osInfo); err != nil {
				tui.PrintWarning("fail2ban setup warning: " + err.Error())
			}
		}
	} else {
		if err := fail2ban.SetupWithFeedback(osInfo); err != nil {
			tui.PrintWarning("fail2ban setup warning: " + err.Error())
		}
	}

	fmt.Println()
	tui.PrintSuccess("Configuration complete!")
	return nil
}

func uninstallInteractive() error {
	for {
		configured := sshdconfig.IsConfigured()
		users, _ := tunneluser.List()
		hasUsers := len(users) > 0

		options := buildUninstallOptions(configured, hasUsers)
		if len(options) == 1 {
			tui.PrintInfo("Nothing to uninstall.")
			return ErrCancelled
		}

		choice, err := tui.RunMenu(tui.MenuConfig{
			Title:   "Uninstall Options",
			Options: options,
		})
		if err != nil {
			return err
		}

		if choice == "" || choice == "back" {
			return ErrCancelled
		}

		var err2 error
		switch choice {
		case "users":
			err2 = uninstallUsers()
		case "config":
			err2 = uninstallConfig()
		case "all":
			err2 = uninstallAll()
		}
		if errors.Is(err2, ErrCancelled) {
			continue
		}
		if err2 != nil {
			tui.PrintError(err2.Error())
		}
		tui.WaitForEnter()
	}
}

func buildUninstallOptions(configured, hasUsers bool) []tui.MenuOption {
	var options []tui.MenuOption

	if hasUsers {
		options = append(options, tui.MenuOption{Label: "Delete all tunnel users", Value: "users"})
	}

	if configured && !hasUsers {
		options = append(options, tui.MenuOption{Label: "Remove configuration (groups, sshd config)", Value: "config"})
	}

	if configured && hasUsers {
		options = append(options, tui.MenuOption{Label: "Complete uninstall (users + configuration)", Value: "all"})
	}

	options = append(options, tui.MenuOption{Label: "Back", Value: "back"})

	return options
}

func uninstallUsers() error {
	users, err := tunneluser.List()
	if err != nil {
		return fmt.Errorf("failed to list users: %w", err)
	}

	if len(users) == 0 {
		tui.PrintInfo("No tunnel users to delete.")
		return nil
	}

	fmt.Println("\nThe following users will be deleted:")
	for _, user := range users {
		fmt.Printf("  - %s (%s)\n", user.Username, user.AuthMode)
	}

	confirm, err := tui.RunConfirm(tui.ConfirmConfig{
		Title: fmt.Sprintf("Delete all %d tunnel users?", len(users)),
	})
	if err != nil {
		return err
	}

	if !confirm {
		return ErrCancelled
	}

	fmt.Println()
	deleted, err := tunneluser.DeleteAllUsers()
	if len(deleted) > 0 {
		fmt.Printf("Deleted users: %v\n", deleted)
	}

	if err != nil {
		return err
	}

	tunneluser.CleanupAuthorizedKeysDir()
	tunneluser.CleanupDenyFiles()

	fmt.Println()
	tui.PrintSuccess("All tunnel users deleted!")
	return nil
}

func uninstallConfig() error {
	hasUsers, _ := tunneluser.GroupsHaveUsers()
	if hasUsers {
		return fmt.Errorf("cannot remove configuration: tunnel users still exist. Delete users first")
	}

	fmt.Println("\nThis will remove:")
	fmt.Println("  - Tunnel groups (sshtunnel-password, sshtunnel-key)")
	fmt.Println("  - sshd hardening configuration files")
	fmt.Println("  - Authorized keys directory (if empty)")

	confirm, err := tui.RunConfirm(tui.ConfirmConfig{
		Title: "Remove all configuration?",
	})
	if err != nil {
		return err
	}

	if !confirm {
		return ErrCancelled
	}

	fmt.Println()

	if sshdconfig.IsConfigured() {
		fmt.Println("Removing sshd configuration...")
		if err := sshdconfig.RemoveAndReload(); err != nil {
			tui.PrintWarning("sshd config removal warning: " + err.Error())
		} else {
			fmt.Println("  sshd configuration removed")
		}
	}

	fmt.Println("Removing tunnel groups...")
	if err := tunneluser.DeleteGroups(); err != nil {
		tui.PrintWarning("Group removal warning: " + err.Error())
	} else {
		fmt.Println("  Tunnel groups removed")
	}

	fmt.Println("Cleaning up authorized_keys.d...")
	tunneluser.CleanupAuthorizedKeysDir()

	fmt.Println("Cleaning up cron.deny and at.deny...")
	tunneluser.CleanupDenyFiles()

	fmt.Println()
	tui.PrintSuccess("Configuration removed!")
	return nil
}

func uninstallAll() error {
	users, _ := tunneluser.List()
	configured := sshdconfig.IsConfigured()

	fmt.Println()
	tui.PrintWarning("This will completely remove sshtun-user configuration:")
	if len(users) > 0 {
		fmt.Printf("  - Delete %d tunnel user(s)\n", len(users))
	}
	if configured {
		fmt.Println("  - Remove tunnel groups")
		fmt.Println("  - Remove sshd hardening configuration")
	}
	fmt.Println("  - Clean up authorized keys and deny files")

	confirm, err := tui.RunConfirm(tui.ConfirmConfig{
		Title: "Proceed with complete uninstall?",
	})
	if err != nil {
		return err
	}

	if !confirm {
		return ErrCancelled
	}

	fmt.Println()

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

	if configured {
		fmt.Println("Removing sshd configuration...")
		if err := sshdconfig.RemoveAndReload(); err != nil {
			tui.PrintWarning("sshd config removal warning: " + err.Error())
		} else {
			fmt.Println("  sshd configuration removed")
		}

		fmt.Println("Removing tunnel groups...")
		if err := tunneluser.DeleteGroups(); err != nil {
			tui.PrintWarning("Group removal warning: " + err.Error())
		} else {
			fmt.Println("  Tunnel groups removed")
		}
	}

	fmt.Println("Cleaning up...")
	tunneluser.CleanupAuthorizedKeysDir()
	tunneluser.CleanupDenyFiles()

	fmt.Println()
	tui.PrintSuccess("Complete uninstall finished!")
	return nil
}

func PromptPassword(username string) (string, error) {
	password, ok, err := tui.RunInput(tui.InputConfig{
		Title:       "Password",
		Description: fmt.Sprintf("Enter password for '%s' (leave empty to auto-generate)", username),
	})
	if err != nil {
		return "", err
	}
	if !ok {
		return "", ErrCancelled
	}

	if password == "" {
		generated, err := tunneluser.GeneratePassword()
		if err != nil {
			return "", fmt.Errorf("failed to generate password: %w", err)
		}
		password = generated
		tui.PrintBox("Generated Password (save this now!)", []string{tui.Code(password)})
	}

	return password, nil
}

func PromptPubkey(username string) (string, error) {
	for {
		key, ok, err := tui.RunInput(tui.InputConfig{
			Title:       "SSH Public Key",
			Description: fmt.Sprintf("Enter public key for '%s' (from ~/.ssh/id_ed25519.pub)", username),
		})
		if err != nil {
			return "", err
		}
		if !ok {
			return "", ErrCancelled
		}

		if key == "" {
			tui.PrintError("public key is required for key-based auth")
			continue
		}
		if err := tunneluser.ValidatePublicKey(key); err != nil {
			tui.PrintError(fmt.Sprintf("invalid public key format: %v", err))
			continue
		}
		return key, nil
	}
}

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
