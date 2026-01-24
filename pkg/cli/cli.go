// Package cli provides the exported interactive CLI for sshtun-user.
// This package can be imported by other projects (like dnstm) to reuse
// the SSH tunnel user management functionality.
package cli

import (
	"fmt"

	"github.com/net2share/go-corelib/osdetect"
	"github.com/net2share/go-corelib/tui"
	"github.com/net2share/sshtun-user/pkg/fail2ban"
	"github.com/net2share/sshtun-user/pkg/sshdconfig"
	"github.com/net2share/sshtun-user/pkg/tunneluser"
)

// Version and BuildTime can be set by the importing package.
var (
	Version   = "dev"
	BuildTime = "unknown"
)

// CreatedUserInfo holds information about a created tunnel user
type CreatedUserInfo struct {
	Username string
	AuthMode string
	Password string // Only set if password auth and auto-generated
}

// RunInteractiveMenu shows the main interactive menu (standalone mode).
// This includes all options: create, update, list, delete, configure, uninstall.
func RunInteractiveMenu() error {
	printBanner()

	osInfo, err := osdetect.Detect()
	if err != nil {
		tui.PrintWarning("Could not detect OS: " + err.Error())
	} else {
		fmt.Printf("Detected OS: %s (package manager: %s)\n", osInfo.ID, osInfo.PackageManager)
	}

	return runMenuLoop(osInfo, true)
}

// ShowUserManagementMenu shows the user management menu.
// If includeConfigure is false, configure option is hidden but still enforced.
// This is what dnstm calls.
func ShowUserManagementMenu() {
	osInfo, _ := osdetect.Detect()
	runMenuLoop(osInfo, false)
}

// runMenuLoop is the shared menu logic for both standalone and embedded modes.
func runMenuLoop(osInfo *osdetect.OSInfo, standaloneMode bool) error {
	for {
		fmt.Println()
		configured := IsConfigured()

		var options []tui.MenuOption

		if standaloneMode {
			// Full menu for standalone sshtun-user
			options = []tui.MenuOption{
				{Key: "1", Label: "Create tunnel user"},
				{Key: "2", Label: "Update tunnel user"},
				{Key: "3", Label: "List tunnel users"},
				{Key: "4", Label: "Delete tunnel user"},
				{Key: "5", Label: "Configure sshd hardening"},
				{Key: "6", Label: "Uninstall"},
				{Key: "0", Label: "Exit"},
			}
		} else {
			// Submenu for dnstm - include configure option
			options = []tui.MenuOption{
				{Key: "1", Label: "Create tunnel user"},
				{Key: "2", Label: "Update tunnel user"},
				{Key: "3", Label: "List tunnel users"},
				{Key: "4", Label: "Delete tunnel user"},
				{Key: "5", Label: "Configure sshd hardening"},
				{Key: "0", Label: "Back to main menu"},
			}
		}

		if !configured {
			fmt.Println()
			tui.PrintWarning("sshd not configured - run 'Configure sshd hardening' (option 5) first")
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
			if err := CreateUserSimple(); err != nil {
				tui.PrintError(err.Error())
			}
			tui.WaitForEnter()
		case "2":
			if !configured {
				tui.PrintError("Please run 'Configure sshd hardening' (option 5) first")
				tui.WaitForEnter()
				continue
			}
			if err := UpdateUserInteractive(); err != nil {
				tui.PrintError(err.Error())
			}
			tui.WaitForEnter()
		case "3":
			if !configured {
				tui.PrintError("Please run 'Configure sshd hardening' (option 5) first")
				tui.WaitForEnter()
				continue
			}
			ListUsersBox()
			tui.WaitForEnter()
		case "4":
			if !configured {
				tui.PrintError("Please run 'Configure sshd hardening' (option 5) first")
				tui.WaitForEnter()
				continue
			}
			if err := DeleteUserInteractive(); err != nil {
				tui.PrintError(err.Error())
			}
			tui.WaitForEnter()
		case "5":
			if err := ConfigureInteractive(osInfo); err != nil {
				tui.PrintError(err.Error())
			}
			tui.WaitForEnter()
		case "6":
			if standaloneMode {
				if err := UninstallInteractive(); err != nil {
					tui.PrintError(err.Error())
				}
			} else {
				tui.PrintError("Invalid option")
			}
		case "0", "q", "quit", "exit", "back":
			if standaloneMode {
				tui.PrintInfo("Goodbye!")
			}
			return nil
		default:
			tui.PrintError("Invalid option")
		}
	}
}

// ConfigureAndCreateUser auto-configures sshd hardening and prompts for user creation.
// Used by dnstm during SSH mode installation - no confirmation for configuration.
// Returns user info if a user was created, nil otherwise.
func ConfigureAndCreateUser() *CreatedUserInfo {
	// Apply sshd hardening (no confirmation - already confirmed by dnstm install)
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

	// Prompt for user creation
	fmt.Println()
	if !tui.Confirm("Create a tunnel user now?", true) {
		return nil
	}

	userInfo, err := createUserWithInfo()
	if err != nil {
		tui.PrintError(err.Error())
		return nil
	}

	return userInfo
}

// createUserWithInfo creates a user and returns their info for display.
func createUserWithInfo() (*CreatedUserInfo, error) {
	fmt.Println()
	username := tui.Prompt("Enter username for tunnel user")
	if username == "" {
		return nil, fmt.Errorf("username required")
	}

	// Check if user already exists
	if tunneluser.Exists(username) {
		return nil, fmt.Errorf("user '%s' already exists", username)
	}

	// Prompt for auth mode
	authMode := PromptAuthMode()

	cfg := &tunneluser.Config{
		Username: username,
		AuthMode: authMode,
	}

	userInfo := &CreatedUserInfo{
		Username: username,
		AuthMode: string(authMode),
	}

	if authMode == tunneluser.AuthModeKey {
		publicKey, err := PromptPubkey(username)
		if err != nil {
			return nil, err
		}
		cfg.PublicKey = publicKey
	} else {
		password, err := PromptPassword(username)
		if err != nil {
			return nil, err
		}
		cfg.Password = password
		userInfo.Password = password // Store for display
	}

	// Create the user
	if err := tunneluser.Create(cfg); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Add AuthorizedKeysFile directive if using key auth
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

// ConfigureInteractive handles configure in interactive mode.
func ConfigureInteractive(osInfo *osdetect.OSInfo) error {
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

// ConfigureCLI applies sshd hardening from CLI.
func ConfigureCLI(noFail2ban bool) error {
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

// CreateUserCLI handles user creation from CLI.
func CreateUserCLI(username, password, publicKey string, noFail2ban bool) error {
	// Check if configured
	if !IsConfigured() {
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
	nonInteractive := password != "" || publicKey != ""

	// In non-interactive mode, username is required
	if nonInteractive && username == "" {
		return fmt.Errorf("username required when using --insecure-password or --pubkey")
	}

	// In interactive mode, prompt for username if not provided
	if !nonInteractive && username == "" {
		var promptErr error
		username, promptErr = PromptUsername()
		if promptErr != nil {
			return promptErr
		}
	}

	// Check if user already exists
	if tunneluser.Exists(username) {
		return fmt.Errorf("user '%s' already exists. Use 'sshtun-user update %s' to modify", username, username)
	}

	// Determine auth mode and get credentials
	cfg := &tunneluser.Config{
		Username: username,
	}

	if publicKey != "" {
		cfg.AuthMode = tunneluser.AuthModeKey
		cfg.PublicKey = publicKey
	} else if password != "" {
		cfg.AuthMode = tunneluser.AuthModePassword
		cfg.Password = password
	} else {
		// Interactive mode - check if fail2ban is already installed
		var promptErr error
		cfg.AuthMode, cfg.Password, cfg.PublicKey, noFail2ban, promptErr = PromptInteractive(username, noFail2ban, fail2ban.IsInstalled())
		if promptErr != nil {
			return promptErr
		}
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

	return nil
}

// UpdateUserCLI handles user update from CLI.
func UpdateUserCLI(username, password, publicKey string) error {
	// Check if configured
	if !IsConfigured() {
		return fmt.Errorf("sshd not configured. Run 'sshtun-user configure' first")
	}

	if username == "" {
		return fmt.Errorf("username required for update command")
	}

	// Check if user exists and is a tunnel user
	if !tunneluser.Exists(username) {
		return fmt.Errorf("user '%s' does not exist", username)
	}

	if !tunneluser.IsTunnelUser(username) {
		return fmt.Errorf("user '%s' is not a tunnel user", username)
	}

	// Get current auth mode
	currentMode, _ := tunneluser.GetAuthMode(username)

	// Non-interactive mode
	if password != "" {
		if err := tunneluser.SetPassword(username, password); err != nil {
			return fmt.Errorf("failed to set password: %w", err)
		}
		if currentMode != tunneluser.AuthModePassword {
			if err := tunneluser.SwitchAuthMode(username, tunneluser.AuthModePassword); err != nil {
				return fmt.Errorf("failed to switch auth mode: %w", err)
			}
		}
		fmt.Printf("Password updated for '%s'\n", username)
		return nil
	}

	if publicKey != "" {
		if err := tunneluser.SetupSSHKey(username, publicKey); err != nil {
			return fmt.Errorf("failed to set SSH key: %w", err)
		}
		if currentMode != tunneluser.AuthModeKey {
			if err := tunneluser.SwitchAuthMode(username, tunneluser.AuthModeKey); err != nil {
				return fmt.Errorf("failed to switch auth mode: %w", err)
			}
		}
		if err := sshdconfig.AddAuthorizedKeysDirective(); err != nil {
			tui.PrintWarning("Could not add AuthorizedKeysFile directive: " + err.Error())
		}
		fmt.Printf("SSH key updated for '%s'\n", username)
		return nil
	}

	// Interactive mode
	return ShowUpdateUserMenu(username, currentMode)
}

// printBanner displays the application banner.
func printBanner() {
	fmt.Println()
	fmt.Printf("SSH Tunnel User Manager v%s (built %s)\n", Version, BuildTime)
	fmt.Println()
}
