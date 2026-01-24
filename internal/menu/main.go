// Package menu provides the interactive menu for sshtun-user.
package menu

import (
	"errors"
	"fmt"

	"github.com/charmbracelet/huh"
	"github.com/net2share/go-corelib/osdetect"
	"github.com/net2share/go-corelib/tui"
	"github.com/net2share/sshtun-user/pkg/fail2ban"
	"github.com/net2share/sshtun-user/pkg/sshdconfig"
	"github.com/net2share/sshtun-user/pkg/tunneluser"
)

// errCancelled is returned when user cancels an operation (no WaitForEnter needed).
var errCancelled = errors.New("cancelled")

// Version and BuildTime are set by cmd package.
var (
	Version   = "dev"
	BuildTime = "unknown"
)

// RunInteractive shows the main interactive menu (standalone mode).
func RunInteractive() error {
	tui.PrintSimpleBanner("SSH Tunnel User Manager", Version, BuildTime)

	osInfo, err := osdetect.Detect()
	if err != nil {
		tui.PrintWarning("Could not detect OS: " + err.Error())
	} else {
		fmt.Printf("Detected OS: %s (package manager: %s)\n", osInfo.ID, osInfo.PackageManager)
	}

	return runMenuLoop(osInfo, true)
}

// runMenuLoop is the shared menu logic for both standalone and embedded modes.
func runMenuLoop(osInfo *osdetect.OSInfo, standaloneMode bool) error {
	for {
		fmt.Println()
		configured := sshdconfig.IsConfigured()

		if !configured {
			fmt.Println()
			tui.PrintWarning("sshd not configured - run 'Configure sshd hardening' first")
		}

		options := buildMenuOptions(standaloneMode)
		var choice string

		err := huh.NewSelect[string]().
			Title("SSH Tunnel User Manager").
			Options(options...).
			Value(&choice).
			Run()

		if err != nil {
			return err
		}

		if choice == "exit" || choice == "back" {
			if standaloneMode {
				tui.PrintInfo("Goodbye!")
			}
			return nil
		}

		err = handleChoice(choice, osInfo, configured, standaloneMode)
		if errors.Is(err, errCancelled) {
			// User cancelled, no need to wait
			continue
		}
		if err != nil {
			tui.PrintError(err.Error())
		}
		tui.WaitForEnter()
	}
}

func buildMenuOptions(standaloneMode bool) []huh.Option[string] {
	if standaloneMode {
		return []huh.Option[string]{
			huh.NewOption("Create tunnel user", "create"),
			huh.NewOption("Update tunnel user", "update"),
			huh.NewOption("List tunnel users", "list"),
			huh.NewOption("Delete tunnel user", "delete"),
			huh.NewOption("Configure sshd hardening", "configure"),
			huh.NewOption("Uninstall", "uninstall"),
			huh.NewOption("Exit", "exit"),
		}
	}
	return []huh.Option[string]{
		huh.NewOption("Create tunnel user", "create"),
		huh.NewOption("Update tunnel user", "update"),
		huh.NewOption("List tunnel users", "list"),
		huh.NewOption("Delete tunnel user", "delete"),
		huh.NewOption("Configure sshd hardening", "configure"),
		huh.NewOption("Back to main menu", "back"),
	}
}

func handleChoice(choice string, osInfo *osdetect.OSInfo, configured, standaloneMode bool) error {
	requiresConfig := choice == "create" || choice == "update" || choice == "list" || choice == "delete"
	if requiresConfig && !configured {
		return fmt.Errorf("please run 'Configure sshd hardening' first")
	}

	switch choice {
	case "create":
		return createUserInteractive()
	case "update":
		return updateUserInteractive()
	case "list":
		listUsersBox()
		return nil
	case "delete":
		return deleteUserInteractive()
	case "configure":
		return configureInteractive(osInfo)
	case "uninstall":
		if standaloneMode {
			return uninstallInteractive()
		}
		return fmt.Errorf("invalid option")
	}
	return nil
}

// createUserInteractive handles user creation in interactive mode.
func createUserInteractive() error {
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
		return err
	}

	// Auth mode selection
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
		return err
	}

	cfg := &tunneluser.Config{
		Username: username,
	}

	if authMode == "key" {
		cfg.AuthMode = tunneluser.AuthModeKey
		publicKey, err := promptPubkey(username)
		if err != nil {
			return err
		}
		cfg.PublicKey = publicKey
	} else {
		cfg.AuthMode = tunneluser.AuthModePassword
		password, err := promptPassword(username)
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
	printClientUsage(username, cfg.AuthMode)
	return nil
}

// updateUserInteractive handles user update in interactive mode.
func updateUserInteractive() error {
	users, err := tunneluser.List()
	if err != nil {
		return fmt.Errorf("failed to list users: %w", err)
	}

	if len(users) == 0 {
		tui.PrintInfo("No tunnel users to update.")
		return nil
	}

	// Build user options - Back first so users are visible below
	options := []huh.Option[string]{
		huh.NewOption("Back", ""),
	}
	for _, user := range users {
		label := fmt.Sprintf("%s (%s)", user.Username, user.AuthMode)
		options = append(options, huh.NewOption(label, user.Username))
	}

	var username string
	err = huh.NewSelect[string]().
		Title("Select user to update").
		Options(options...).
		Height(len(options) + 2).
		Value(&username).
		Run()
	if err != nil {
		return err
	}

	if username == "" {
		return errCancelled
	}

	currentMode, _ := tunneluser.GetAuthMode(username)
	return showUpdateUserMenu(username, currentMode)
}

func showUpdateUserMenu(username string, currentMode tunneluser.AuthMode) error {
	fmt.Printf("\nUpdating user '%s' (current auth: %s)\n", username, currentMode)

	var choice string
	err := huh.NewSelect[string]().
		Title("What would you like to update?").
		Options(
			huh.NewOption("Back", "back"),
			huh.NewOption("Change password (switch to password auth if needed)", "password"),
			huh.NewOption("Change SSH key (switch to key auth if needed)", "key"),
		).
		Value(&choice).
		Run()
	if err != nil {
		return err
	}

	switch choice {
	case "password":
		return updateUserPassword(username, currentMode)
	case "key":
		return updateUserKey(username, currentMode)
	default:
		return errCancelled
	}
}

func updateUserPassword(username string, currentMode tunneluser.AuthMode) error {
	password, err := promptPassword(username)
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
	printClientUsage(username, tunneluser.AuthModePassword)
	return nil
}

func updateUserKey(username string, currentMode tunneluser.AuthMode) error {
	publicKey, err := promptPubkey(username)
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
	printClientUsage(username, tunneluser.AuthModeKey)
	return nil
}

func listUsersBox() {
	fmt.Println()
	users, err := tunneluser.List()
	if err != nil {
		tui.PrintError("Failed to list users: " + err.Error())
		return
	}

	if len(users) == 0 {
		tui.PrintInfo("No tunnel users found.")
		return
	}

	lines := make([]string, len(users))
	for i, user := range users {
		lines[i] = fmt.Sprintf("%s (%s auth)", user.Username, user.AuthMode)
	}

	tui.PrintBox("Tunnel Users", lines)
}

// deleteUserInteractive handles user deletion in interactive mode.
func deleteUserInteractive() error {
	users, err := tunneluser.List()
	if err != nil {
		return fmt.Errorf("failed to list users: %w", err)
	}

	if len(users) == 0 {
		tui.PrintInfo("No tunnel users to delete.")
		return nil
	}

	// Build user options - Back first so users are visible below
	options := []huh.Option[string]{
		huh.NewOption("Back", ""),
	}
	for _, user := range users {
		label := fmt.Sprintf("%s (%s)", user.Username, user.AuthMode)
		options = append(options, huh.NewOption(label, user.Username))
	}

	var username string
	err = huh.NewSelect[string]().
		Title("Select user to delete").
		Options(options...).
		Height(len(options) + 2).
		Value(&username).
		Run()
	if err != nil {
		return err
	}

	if username == "" {
		return errCancelled
	}

	var confirm bool
	err = huh.NewConfirm().
		Title(fmt.Sprintf("Delete user '%s'?", username)).
		Value(&confirm).
		Run()
	if err != nil {
		return err
	}

	if !confirm {
		return errCancelled
	}

	if err := tunneluser.Delete(username); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	tui.PrintSuccess(fmt.Sprintf("User '%s' deleted successfully!", username))
	return nil
}

// configureInteractive handles configure in interactive mode.
func configureInteractive(osInfo *osdetect.OSInfo) error {
	fmt.Println()
	tui.PrintInfo("Applying sshd hardening configuration...")

	if err := sshdconfig.Configure(); err != nil {
		return err
	}

	if !fail2ban.IsInstalled() {
		var enableFail2ban bool
		err := huh.NewConfirm().
			Title("Enable fail2ban brute-force protection?").
			Description("Bans IPs after 5 failed login attempts").
			Value(&enableFail2ban).
			Run()
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

// uninstallInteractive shows the uninstall submenu.
func uninstallInteractive() error {
	for {
		var choice string
		err := huh.NewSelect[string]().
			Title("Uninstall Options").
			Options(
				huh.NewOption("Delete all tunnel users", "users"),
				huh.NewOption("Remove configuration (groups, sshd config)", "config"),
				huh.NewOption("Complete uninstall (users + configuration)", "all"),
				huh.NewOption("Back", "back"),
			).
			Value(&choice).
			Run()
		if err != nil {
			return err
		}

		if choice == "back" {
			return errCancelled
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
		if errors.Is(err2, errCancelled) {
			continue
		}
		if err2 != nil {
			tui.PrintError(err2.Error())
		}
		tui.WaitForEnter()
	}
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

	var confirm bool
	err = huh.NewConfirm().
		Title(fmt.Sprintf("Delete all %d tunnel users?", len(users))).
		Value(&confirm).
		Run()
	if err != nil {
		return err
	}

	if !confirm {
		return errCancelled
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

	var confirm bool
	err := huh.NewConfirm().
		Title("Remove all configuration?").
		Value(&confirm).
		Run()
	if err != nil {
		return err
	}

	if !confirm {
		return errCancelled
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

	fmt.Println()
	tui.PrintWarning("This will completely remove sshtun-user configuration:")
	if len(users) > 0 {
		fmt.Printf("  - Delete %d tunnel user(s)\n", len(users))
	}
	fmt.Println("  - Remove tunnel groups")
	fmt.Println("  - Remove sshd hardening configuration")
	fmt.Println("  - Clean up authorized keys and deny files")

	var confirm bool
	err := huh.NewConfirm().
		Title("Proceed with complete uninstall?").
		Value(&confirm).
		Run()
	if err != nil {
		return err
	}

	if !confirm {
		return errCancelled
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

	fmt.Println("Cleaning up...")
	tunneluser.CleanupAuthorizedKeysDir()
	tunneluser.CleanupDenyFiles()

	fmt.Println()
	tui.PrintSuccess("Complete uninstall finished!")
	return nil
}

// promptPassword prompts for a password or generates one.
func promptPassword(username string) (string, error) {
	var password string
	err := huh.NewInput().
		Title("Password").
		Description(fmt.Sprintf("Enter password for '%s' (leave empty to auto-generate)", username)).
		Value(&password).
		Run()
	if err != nil {
		return "", err
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

// promptPubkey prompts for an SSH public key.
func promptPubkey(username string) (string, error) {
	var key string
	err := huh.NewInput().
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
		return "", err
	}
	return key, nil
}

// printClientUsage prints SSH client usage examples.
func printClientUsage(username string, authMode tunneluser.AuthMode) {
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
