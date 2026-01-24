package cmd

import (
	"fmt"

	"github.com/charmbracelet/huh"
	"github.com/net2share/go-corelib/osdetect"
	"github.com/net2share/go-corelib/tui"
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

	printClientUsage(username, cfg.AuthMode)
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
	}

	var authMode string
	err := huh.NewSelect[string]().
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

	// Only prompt for fail2ban if not explicitly disabled and not already installed
	if !createNoFail2bn && !fail2ban.IsInstalled() {
		var enableFail2ban bool
		err = huh.NewConfirm().
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
	printClientUsage(username, cfg.AuthMode)
	return nil
}

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
