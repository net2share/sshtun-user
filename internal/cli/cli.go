// Package cli provides the command-line interface for sshtun-user.
package cli

import (
	"fmt"

	"github.com/net2share/go-corelib/osdetect"
	"github.com/net2share/go-corelib/tui"
	"github.com/net2share/sshtun-user/pkg/fail2ban"
	"github.com/net2share/sshtun-user/pkg/sshdconfig"
	"github.com/net2share/sshtun-user/pkg/tunneluser"
)

// Version and BuildTime are set at build time.
var (
	Version   = "dev"
	BuildTime = "unknown"
)

// Command represents the CLI command to run.
type Command string

const (
	CommandNone           Command = ""
	CommandCreate         Command = "create"
	CommandUpdate         Command = "update"
	CommandList           Command = "list"
	CommandDelete         Command = "delete"
	CommandConfigure      Command = "configure"
	CommandUninstall      Command = "uninstall"
	CommandUninstallUsers Command = "uninstall-users"
	CommandUninstallAll   Command = "uninstall-all"
)

// Options holds the parsed command-line options.
type Options struct {
	Command     Command
	Username    string
	Password    string
	PublicKey   string
	NoFail2ban  bool
	ShowHelp    bool
	ShowVersion bool
}

// Run is the main entry point for the CLI.
func Run(args []string) error {
	opts, err := parseArgs(args)
	if err != nil {
		return err
	}

	if opts.ShowHelp {
		printUsage()
		return nil
	}

	if opts.ShowVersion {
		fmt.Printf("sshtun-user v%s (built %s)\n", Version, BuildTime)
		return nil
	}

	// Must run as root
	if !osdetect.IsRoot() {
		return fmt.Errorf("run as root")
	}

	// No command specified - show interactive menu
	if opts.Command == CommandNone {
		return runInteractiveMenu()
	}

	// Route to appropriate command handler
	switch opts.Command {
	case CommandList:
		return runList()
	case CommandDelete:
		return runDelete(opts.Username)
	case CommandConfigure:
		return runConfigure(opts.NoFail2ban)
	case CommandCreate:
		return runCreate(opts)
	case CommandUpdate:
		return runUpdate(opts)
	case CommandUninstall:
		return runUninstallCLI("")
	case CommandUninstallUsers:
		return runUninstallCLI("users")
	case CommandUninstallAll:
		return runUninstallCLI("all")
	default:
		return fmt.Errorf("unknown command: %s", opts.Command)
	}
}

// printBanner displays the application banner.
func printBanner() {
	fmt.Println()
	fmt.Printf("SSH Tunnel User Manager v%s (built %s)\n", Version, BuildTime)
	fmt.Println()
}

// runInteractiveMenu shows the main interactive menu.
func runInteractiveMenu() error {
	printBanner()

	osInfo, err := osdetect.Detect()
	if err != nil {
		tui.PrintWarning("Could not detect OS: " + err.Error())
	} else {
		fmt.Printf("Detected OS: %s (package manager: %s)\n", osInfo.ID, osInfo.PackageManager)
	}

	for {
		fmt.Println()
		configured := isConfigured()

		options := []tui.MenuOption{
			{Key: "1", Label: "Create tunnel user"},
			{Key: "2", Label: "Update tunnel user"},
			{Key: "3", Label: "List tunnel users"},
			{Key: "4", Label: "Delete tunnel user"},
			{Key: "5", Label: "Configure sshd hardening"},
			{Key: "6", Label: "Uninstall"},
			{Key: "0", Label: "Exit"},
		}

		if !configured {
			fmt.Println()
			tui.PrintWarning("sshd not configured - run 'Configure' (option 5) first before managing users")
		}

		tui.ShowMenu(options)
		choice := tui.Prompt("Select option")

		switch choice {
		case "1":
			if !configured {
				tui.PrintError("Please run 'Configure sshd hardening' (option 5) first")
				tui.WaitForEnter()
				continue
			}
			if err := runCreateInteractive(osInfo); err != nil {
				tui.PrintError(err.Error())
			}
			tui.WaitForEnter()
		case "2":
			if !configured {
				tui.PrintError("Please run 'Configure sshd hardening' (option 5) first")
				tui.WaitForEnter()
				continue
			}
			if err := runUpdateInteractive(); err != nil {
				tui.PrintError(err.Error())
			}
			tui.WaitForEnter()
		case "3":
			if !configured {
				tui.PrintError("Please run 'Configure sshd hardening' (option 5) first")
				tui.WaitForEnter()
				continue
			}
			if err := runList(); err != nil {
				tui.PrintError(err.Error())
			}
			tui.WaitForEnter()
		case "4":
			if !configured {
				tui.PrintError("Please run 'Configure sshd hardening' (option 5) first")
				tui.WaitForEnter()
				continue
			}
			if err := runDeleteInteractive(); err != nil {
				tui.PrintError(err.Error())
			}
			tui.WaitForEnter()
		case "5":
			if err := runConfigureInteractive(osInfo); err != nil {
				tui.PrintError(err.Error())
			}
			tui.WaitForEnter()
		case "6":
			if err := runUninstallInteractive(); err != nil {
				tui.PrintError(err.Error())
			}
		case "0", "q", "quit", "exit":
			tui.PrintInfo("Goodbye!")
			return nil
		default:
			tui.PrintError("Invalid option")
		}
	}
}

// isConfigured checks if sshd hardening has been applied.
func isConfigured() bool {
	return sshdconfig.IsConfigured()
}

// runConfigureInteractive handles configure in interactive mode.
func runConfigureInteractive(osInfo *osdetect.OSInfo) error {
	fmt.Println()
	tui.PrintInfo("Applying sshd hardening configuration...")

	if err := sshdconfig.Configure(); err != nil {
		return err
	}

	// Prompt for fail2ban
	fmt.Println()
	if !fail2ban.IsInstalled() {
		if tui.Confirm("Enable fail2ban brute-force protection?", true) {
			if err := fail2ban.SetupWithFeedback(osInfo); err != nil {
				tui.PrintWarning("fail2ban setup warning: " + err.Error())
			}
		}
	} else {
		// fail2ban already installed, just configure it
		if err := fail2ban.SetupWithFeedback(osInfo); err != nil {
			tui.PrintWarning("fail2ban setup warning: " + err.Error())
		}
	}

	fmt.Println()
	tui.PrintSuccess("Configuration complete!")
	return nil
}

// runCreateInteractive handles user creation in interactive mode.
func runCreateInteractive(osInfo *osdetect.OSInfo) error {
	fmt.Println()
	username := promptUsername()
	if username == "" {
		return fmt.Errorf("username required")
	}

	// Check if user already exists
	if tunneluser.Exists(username) {
		return fmt.Errorf("user '%s' already exists. Use 'Update tunnel user' to modify", username)
	}

	// Interactive mode - prompt for auth mode
	cfg := &tunneluser.Config{
		Username: username,
	}

	cfg.AuthMode, cfg.Password, cfg.PublicKey, _ = promptInteractive(username, false, fail2ban.IsInstalled())

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
	printClientUsage(username, cfg.AuthMode)
	fmt.Println()
	tui.PrintSuccess(fmt.Sprintf("User '%s' created successfully!", username))

	return nil
}

// runUpdateInteractive handles user update in interactive mode.
func runUpdateInteractive() error {
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

	return runUpdateUserMenu(username, currentMode)
}

// runUpdateUserMenu shows the update menu for a specific user.
func runUpdateUserMenu(username string, currentMode tunneluser.AuthMode) error {
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
		return updateUserPassword(username, currentMode)
	case "2":
		return updateUserKey(username, currentMode)
	case "0":
		tui.PrintInfo("Cancelled")
		return nil
	default:
		return fmt.Errorf("invalid option")
	}
}

// updateUserPassword updates a user's password and switches to password auth if needed.
func updateUserPassword(username string, currentMode tunneluser.AuthMode) error {
	password := promptPassword(username)

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
	printClientUsage(username, tunneluser.AuthModePassword)
	return nil
}

// updateUserKey updates a user's SSH key and switches to key auth if needed.
func updateUserKey(username string, currentMode tunneluser.AuthMode) error {
	publicKey := promptPubkey(username)

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
	printClientUsage(username, tunneluser.AuthModeKey)
	return nil
}

// runDeleteInteractive handles user deletion in interactive mode.
func runDeleteInteractive() error {
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

// runUninstallInteractive shows the uninstall submenu.
func runUninstallInteractive() error {
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
			if err := uninstallUsers(); err != nil {
				tui.PrintError(err.Error())
			}
			tui.WaitForEnter()
		case "2":
			if err := uninstallConfig(); err != nil {
				tui.PrintError(err.Error())
			}
			tui.WaitForEnter()
		case "3":
			if err := uninstallAll(); err != nil {
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

// uninstallUsers deletes all tunnel users.
func uninstallUsers() error {
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

// uninstallConfig removes configuration (groups, sshd config).
func uninstallConfig() error {
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

// uninstallAll performs complete uninstall (users + config).
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

// runUninstallCLI handles uninstall from CLI.
func runUninstallCLI(subcommand string) error {
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

// runCreate handles user creation (CLI mode).
func runCreate(opts *Options) error {
	// Check if configured
	if !isConfigured() {
		return fmt.Errorf("sshd not configured. Run 'sshtun-user configure' first")
	}

	// Detect OS
	osInfo, err := osdetect.Detect()
	if err != nil {
		tui.PrintWarning("Could not detect OS: " + err.Error())
	} else {
		fmt.Printf("Detected OS: %s (package manager: %s)\n", osInfo.ID, osInfo.PackageManager)
	}

	// Determine if we're in non-interactive mode (password or pubkey provided via CLI)
	nonInteractive := opts.Password != "" || opts.PublicKey != ""

	// In non-interactive mode, username is required
	if nonInteractive && opts.Username == "" {
		return fmt.Errorf("username required when using --insecure-password or --pubkey")
	}

	// In interactive mode, prompt for username if not provided
	if !nonInteractive && opts.Username == "" {
		opts.Username = promptUsername()
		if opts.Username == "" {
			return fmt.Errorf("username required")
		}
	}

	// Check if user already exists
	if tunneluser.Exists(opts.Username) {
		return fmt.Errorf("user '%s' already exists. Use 'sshtun-user update %s' to modify", opts.Username, opts.Username)
	}

	// Determine auth mode and get credentials
	cfg := &tunneluser.Config{
		Username: opts.Username,
	}

	if opts.PublicKey != "" {
		cfg.AuthMode = tunneluser.AuthModeKey
		cfg.PublicKey = opts.PublicKey
	} else if opts.Password != "" {
		cfg.AuthMode = tunneluser.AuthModePassword
		cfg.Password = opts.Password
	} else {
		// Interactive mode - check if fail2ban is already installed
		cfg.AuthMode, cfg.Password, cfg.PublicKey, opts.NoFail2ban = promptInteractive(opts.Username, opts.NoFail2ban, fail2ban.IsInstalled())
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
	printClientUsage(opts.Username, cfg.AuthMode)

	return nil
}

// runUpdate handles user update (CLI mode).
func runUpdate(opts *Options) error {
	// Check if configured
	if !isConfigured() {
		return fmt.Errorf("sshd not configured. Run 'sshtun-user configure' first")
	}

	if opts.Username == "" {
		return fmt.Errorf("username required for update command")
	}

	// Check if user exists and is a tunnel user
	if !tunneluser.Exists(opts.Username) {
		return fmt.Errorf("user '%s' does not exist", opts.Username)
	}

	if !tunneluser.IsTunnelUser(opts.Username) {
		return fmt.Errorf("user '%s' is not a tunnel user", opts.Username)
	}

	// Get current auth mode
	currentMode, _ := tunneluser.GetAuthMode(opts.Username)

	// Non-interactive mode
	if opts.Password != "" {
		if err := tunneluser.SetPassword(opts.Username, opts.Password); err != nil {
			return fmt.Errorf("failed to set password: %w", err)
		}
		if currentMode != tunneluser.AuthModePassword {
			if err := tunneluser.SwitchAuthMode(opts.Username, tunneluser.AuthModePassword); err != nil {
				return fmt.Errorf("failed to switch auth mode: %w", err)
			}
		}
		fmt.Printf("Password updated for '%s'\n", opts.Username)
		return nil
	}

	if opts.PublicKey != "" {
		if err := tunneluser.SetupSSHKey(opts.Username, opts.PublicKey); err != nil {
			return fmt.Errorf("failed to set SSH key: %w", err)
		}
		if currentMode != tunneluser.AuthModeKey {
			if err := tunneluser.SwitchAuthMode(opts.Username, tunneluser.AuthModeKey); err != nil {
				return fmt.Errorf("failed to switch auth mode: %w", err)
			}
		}
		if err := sshdconfig.AddAuthorizedKeysDirective(); err != nil {
			tui.PrintWarning("Could not add AuthorizedKeysFile directive: " + err.Error())
		}
		fmt.Printf("SSH key updated for '%s'\n", opts.Username)
		return nil
	}

	// Interactive mode
	return runUpdateUserMenu(opts.Username, currentMode)
}

// runList lists all tunnel users.
func runList() error {
	// Check if configured
	if !isConfigured() {
		return fmt.Errorf("sshd not configured. Run 'sshtun-user configure' first")
	}

	users, err := tunneluser.List()
	if err != nil {
		return fmt.Errorf("failed to list users: %w", err)
	}

	if len(users) == 0 {
		fmt.Println("No tunnel users found.")
		return nil
	}

	fmt.Println("Tunnel users:")
	for _, user := range users {
		fmt.Printf("  %s (%s)\n", user.Username, user.AuthMode)
	}

	return nil
}

// runDelete deletes a tunnel user.
func runDelete(username string) error {
	// Check if configured
	if !isConfigured() {
		return fmt.Errorf("sshd not configured. Run 'sshtun-user configure' first")
	}

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

// runConfigure applies sshd hardening without creating a user.
func runConfigure(noFail2ban bool) error {
	osInfo, err := osdetect.Detect()
	if err != nil {
		tui.PrintWarning("Could not detect OS: " + err.Error())
	} else {
		fmt.Printf("Detected OS: %s (package manager: %s)\n", osInfo.ID, osInfo.PackageManager)
	}

	if err := sshdconfig.Configure(); err != nil {
		return err
	}
	if !noFail2ban {
		if err := fail2ban.SetupWithFeedback(osInfo); err != nil {
			tui.PrintWarning("fail2ban setup warning: " + err.Error())
		}
	}
	fmt.Println()
	fmt.Println("Configuration complete!")
	return nil
}

func parseArgs(args []string) (*Options, error) {
	opts := &Options{
		Command: CommandNone, // No command = interactive mode
	}

	i := 0

	// Check for subcommand as first argument
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		switch args[0] {
		case "create":
			opts.Command = CommandCreate
			i++
		case "update":
			opts.Command = CommandUpdate
			i++
		case "list":
			opts.Command = CommandList
			i++
		case "delete":
			opts.Command = CommandDelete
			i++
		case "configure":
			opts.Command = CommandConfigure
			i++
		case "uninstall":
			opts.Command = CommandUninstall
			i++
			// Check for uninstall subcommand
			if i < len(args) && len(args[i]) > 0 && args[i][0] != '-' {
				switch args[i] {
				case "users":
					opts.Command = CommandUninstallUsers
					i++
				case "all":
					opts.Command = CommandUninstallAll
					i++
				}
			}
		default:
			// Unknown command
			return nil, fmt.Errorf("unknown command: %s\nRun 'sshtun-user --help' for usage", args[0])
		}
	}

	// Parse remaining arguments
	for ; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--help", "-h":
			opts.ShowHelp = true
		case "--version", "-v":
			opts.ShowVersion = true
		case "--insecure-password":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--insecure-password requires a value")
			}
			i++
			opts.Password = args[i]
		case "--pubkey":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--pubkey requires a value")
			}
			i++
			opts.PublicKey = args[i]
		case "--no-fail2ban":
			opts.NoFail2ban = true
		default:
			if len(arg) > 0 && arg[0] == '-' {
				return nil, fmt.Errorf("unknown option: %s", arg)
			}
			if opts.Username == "" {
				opts.Username = arg
			} else {
				return nil, fmt.Errorf("unexpected argument: %s", arg)
			}
		}
	}

	// Validate: can't have both password and pubkey
	if opts.Password != "" && opts.PublicKey != "" {
		return nil, fmt.Errorf("cannot specify both --insecure-password and --pubkey")
	}

	// Validate: delete command requires username
	if opts.Command == CommandDelete && opts.Username == "" {
		return nil, fmt.Errorf("delete command requires a username")
	}

	// Validate: update command requires username
	if opts.Command == CommandUpdate && opts.Username == "" {
		return nil, fmt.Errorf("update command requires a username")
	}

	return opts, nil
}

func printUsage() {
	fmt.Printf(`sshtun-user v%s (built %s)
SSH Tunnel User Setup - https://github.com/net2share/sshtun-user

Usage: sshtun-user [command] [options]

Commands:
  configure             Apply sshd hardening (run this first)
  create <username>     Create a new tunnel user
  update <username>     Update an existing tunnel user
  list                  List all tunnel users
  delete <username>     Delete a tunnel user
  uninstall [subcommand]  Uninstall components

Uninstall Subcommands:
  uninstall             Show uninstall help
  uninstall users       Delete all tunnel users
  uninstall all         Complete uninstall (users + configuration)

If no command is specified, an interactive menu is shown.

Options:
  --insecure-password <pass>  Set password (WARNING: visible in process list/history)
  --pubkey <key>              Set public key for key-based auth
  --no-fail2ban               Skip fail2ban installation/configuration
  --version, -v               Show version
  --help, -h                  Show this help

Examples:
  sshtun-user                            # Interactive menu
  sshtun-user configure                  # Apply sshd hardening
  sshtun-user create myuser              # Create user with prompts
  sshtun-user update myuser              # Update user interactively
  sshtun-user list                       # List all tunnel users
  sshtun-user delete myuser              # Delete a tunnel user
  sshtun-user uninstall users            # Delete all tunnel users
  sshtun-user uninstall all              # Complete uninstall

Notes:
  - Run 'configure' first before creating/listing/deleting users
  - Use 'create' for new users, 'update' for existing users
  - Tunnel users are detected by their membership in tunnel groups
  - fail2ban is enabled by default for brute-force protection
`, Version, BuildTime)
}

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
