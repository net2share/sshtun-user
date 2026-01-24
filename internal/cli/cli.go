// Package cli provides the command-line interface for sshtun-user.
// This internal package handles argument parsing and delegates to pkg/cli.
package cli

import (
	"fmt"

	"github.com/net2share/go-corelib/osdetect"
	pkgcli "github.com/net2share/sshtun-user/pkg/cli"
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

	// Set version info for pkg/cli
	pkgcli.Version = Version
	pkgcli.BuildTime = BuildTime

	// No command specified - show interactive menu
	if opts.Command == CommandNone {
		return pkgcli.RunInteractiveMenu()
	}

	// Route to appropriate command handler
	switch opts.Command {
	case CommandList:
		if !pkgcli.IsConfigured() {
			return fmt.Errorf("sshd not configured. Run 'sshtun-user configure' first")
		}
		return pkgcli.ListUsers()
	case CommandDelete:
		if !pkgcli.IsConfigured() {
			return fmt.Errorf("sshd not configured. Run 'sshtun-user configure' first")
		}
		return pkgcli.DeleteUserCLI(opts.Username)
	case CommandConfigure:
		return pkgcli.ConfigureCLI(opts.NoFail2ban)
	case CommandCreate:
		return pkgcli.CreateUserCLI(opts.Username, opts.Password, opts.PublicKey, opts.NoFail2ban)
	case CommandUpdate:
		return pkgcli.UpdateUserCLI(opts.Username, opts.Password, opts.PublicKey)
	case CommandUninstall:
		return pkgcli.UninstallCLI("")
	case CommandUninstallUsers:
		return pkgcli.UninstallCLI("users")
	case CommandUninstallAll:
		return pkgcli.UninstallCLI("all")
	default:
		return fmt.Errorf("unknown command: %s", opts.Command)
	}
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
