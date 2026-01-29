package cmd

import (
	"errors"
	"fmt"

	"github.com/net2share/go-corelib/osdetect"
	"github.com/net2share/go-corelib/tui"
	"github.com/net2share/sshtun-user/internal/menu"
	"github.com/net2share/sshtun-user/pkg/fail2ban"
	"github.com/net2share/sshtun-user/pkg/sshdconfig"
	"github.com/net2share/sshtun-user/pkg/tunneluser"
	"github.com/spf13/cobra"
)

var (
	createPassword  string
	createPubkey    string
	createNoFail2bn bool
)

var createCmd = &cobra.Command{
	Use:   "create [username]",
	Short: "Create a new tunnel user",
	RunE:  runCreate,
}

func init() {
	createCmd.Flags().StringVar(&createPassword, "insecure-password", "", "Set password (WARNING: visible in process list)")
	createCmd.Flags().StringVar(&createPubkey, "pubkey", "", "Set public key for key-based auth")
	createCmd.Flags().BoolVar(&createNoFail2bn, "no-fail2ban", false, "Skip fail2ban installation")
}

func runCreate(cmd *cobra.Command, args []string) error {
	if err := osdetect.RequireRoot(); err != nil {
		return err
	}

	if !sshdconfig.IsConfigured() {
		return fmt.Errorf("sshd not configured. Run 'sshtun-user configure' first")
	}

	osInfo, err := osdetect.Detect()
	if err != nil {
		tui.PrintWarning("Could not detect OS: " + err.Error())
	} else {
		fmt.Printf("Detected OS: %s (package manager: %s)\n", osInfo.ID, osInfo.PackageManager)
	}

	// Determine CLI vs interactive mode
	cliMode := cmd.Flags().Changed("insecure-password") || cmd.Flags().Changed("pubkey")

	if cliMode {
		return runCreateCLI(args)
	}
	return runCreateInteractive(args, osInfo)
}

func runCreateCLI(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("username required when using --insecure-password or --pubkey")
	}
	username := args[0]

	if createPassword != "" && createPubkey != "" {
		return fmt.Errorf("cannot specify both --insecure-password and --pubkey")
	}

	if tunneluser.Exists(username) {
		return fmt.Errorf("user '%s' already exists. Use 'sshtun-user update %s' to modify", username, username)
	}

	cfg := &tunneluser.Config{
		Username: username,
	}

	if createPubkey != "" {
		cfg.AuthMode = tunneluser.AuthModeKey
		cfg.PublicKey = createPubkey
	} else {
		cfg.AuthMode = tunneluser.AuthModePassword
		cfg.Password = createPassword
	}

	if err := tunneluser.Create(cfg); err != nil {
		return err
	}

	if cfg.AuthMode == tunneluser.AuthModeKey {
		if err := sshdconfig.AddAuthorizedKeysDirective(); err != nil {
			tui.PrintWarning("Could not add AuthorizedKeysFile directive: " + err.Error())
		}
	}

	menu.PrintClientUsage(username, cfg.AuthMode)
	return nil
}

func runCreateInteractive(args []string, osInfo *osdetect.OSInfo) error {
	var username string
	if len(args) > 0 {
		username = args[0]
		if tunneluser.Exists(username) {
			return fmt.Errorf("user '%s' already exists. Use 'sshtun-user update %s' to modify", username, username)
		}
	} else {
		for {
			value, ok, err := tui.RunInput(tui.InputConfig{
				Title:       "Username",
				Description: "Enter username for tunnel user",
			})
			if err != nil {
				return err
			}
			if !ok || value == "" {
				return fmt.Errorf("username required")
			}

			// Validate
			if tunneluser.Exists(value) {
				tui.PrintError(fmt.Sprintf("user '%s' already exists", value))
				continue
			}
			username = value
			break
		}
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
		return fmt.Errorf("authentication method required")
	}

	cfg := &tunneluser.Config{
		Username: username,
	}

	if authMode == "key" {
		cfg.AuthMode = tunneluser.AuthModeKey
		publicKey, err := menu.PromptPubkey(username)
		if errors.Is(err, menu.ErrCancelled) {
			return fmt.Errorf("public key input cancelled")
		}
		if err != nil {
			return err
		}
		cfg.PublicKey = publicKey
	} else {
		cfg.AuthMode = tunneluser.AuthModePassword
		password, err := menu.PromptPassword(username)
		if errors.Is(err, menu.ErrCancelled) {
			return fmt.Errorf("password input cancelled")
		}
		if err != nil {
			return err
		}
		cfg.Password = password
	}

	// Only prompt for fail2ban if not explicitly disabled and not already installed
	if !createNoFail2bn && !fail2ban.IsInstalled() {
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
	}

	if err := tunneluser.Create(cfg); err != nil {
		return err
	}

	if cfg.AuthMode == tunneluser.AuthModeKey {
		if err := sshdconfig.AddAuthorizedKeysDirective(); err != nil {
			tui.PrintWarning("Could not add AuthorizedKeysFile directive: " + err.Error())
		}
	}

	fmt.Println()
	tui.PrintSuccess(fmt.Sprintf("User '%s' created successfully!", username))
	menu.PrintClientUsage(username, cfg.AuthMode)
	return nil
}

