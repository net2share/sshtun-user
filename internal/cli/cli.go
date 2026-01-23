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

// Version is set at build time.
var Version = "dev"

// Options holds the parsed command-line options.
type Options struct {
	Username      string
	Password      string
	PublicKey     string
	ConfigureOnly bool
	NoFail2ban    bool
	ShowHelp      bool
	ShowVersion   bool
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
		fmt.Printf("sshtun-user v%s\n", Version)
		return nil
	}

	// Must run as root
	if !osdetect.IsRoot() {
		return fmt.Errorf("run as root")
	}

	// Detect OS
	osInfo, err := osdetect.Detect()
	if err != nil {
		tui.PrintWarning("Could not detect OS: " + err.Error())
	} else {
		fmt.Printf("Detected OS: %s (package manager: %s)\n", osInfo.ID, osInfo.PackageManager)
	}

	// Configure-only mode
	if opts.ConfigureOnly {
		if err := sshdconfig.Configure(); err != nil {
			return err
		}
		if !opts.NoFail2ban {
			if err := fail2ban.SetupWithFeedback(osInfo); err != nil {
				tui.PrintWarning("fail2ban setup warning: " + err.Error())
			}
		}
		fmt.Println()
		fmt.Println("Configuration complete (no user created)")
		return nil
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

	// Configure sshd
	if err := sshdconfig.Configure(); err != nil {
		return err
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

	// Configure fail2ban
	if !opts.NoFail2ban {
		if err := fail2ban.SetupWithFeedback(osInfo); err != nil {
			tui.PrintWarning("fail2ban setup warning: " + err.Error())
		}
	} else {
		fmt.Println("Skipping fail2ban configuration (disabled)")
	}

	// Print client usage
	printClientUsage(opts.Username, cfg.AuthMode)

	return nil
}

func parseArgs(args []string) (*Options, error) {
	opts := &Options{}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--configure-only":
			opts.ConfigureOnly = true
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

	return opts, nil
}

func printUsage() {
	fmt.Printf(`sshtun-user v%s - SSH Tunnel User Setup
https://github.com/net2share/sshtun-user

Usage: sshtun-user [username] [options]
       sshtun-user --configure-only [--no-fail2ban]

Options:
  --insecure-password <pass>  Set password (WARNING: visible in process list/history)
  --pubkey <key>              Set public key for key-based auth
  --no-fail2ban               Skip fail2ban installation/configuration
  --configure-only            Only apply sshd hardening, no user creation
  --version, -v               Show version
  --help, -h                  Show this help

Notes:
  - In interactive mode (no --insecure-password or --pubkey), username is prompted
  - In non-interactive mode, username is required as first argument
  - Provide either --insecure-password OR --pubkey, not both
  - In interactive password mode, leaving password empty auto-generates one
  - fail2ban is enabled by default for brute-force protection
`, Version)
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
