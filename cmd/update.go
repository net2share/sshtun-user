package cmd

import (
	"fmt"

	"github.com/charmbracelet/huh"
	"github.com/net2share/go-corelib/osdetect"
	"github.com/net2share/go-corelib/tui"
	"github.com/net2share/sshtun-user/pkg/sshdconfig"
	"github.com/net2share/sshtun-user/pkg/tunneluser"
	"github.com/spf13/cobra"
)

var (
	updatePassword string
	updatePubkey   string
)

var updateCmd = &cobra.Command{
	Use:   "update <username>",
	Short: "Update an existing tunnel user",
	Args:  cobra.ExactArgs(1),
	RunE:  runUpdate,
}

func init() {
	updateCmd.Flags().StringVar(&updatePassword, "insecure-password", "", "Set new password")
	updateCmd.Flags().StringVar(&updatePubkey, "pubkey", "", "Set new public key")
}

func runUpdate(cmd *cobra.Command, args []string) error {
	if err := osdetect.RequireRoot(); err != nil {
		return err
	}

	if !sshdconfig.IsConfigured() {
		return fmt.Errorf("sshd not configured. Run 'sshtun-user configure' first")
	}

	username := args[0]

	if !tunneluser.Exists(username) {
		return fmt.Errorf("user '%s' does not exist", username)
	}

	if !tunneluser.IsTunnelUser(username) {
		return fmt.Errorf("user '%s' is not a tunnel user", username)
	}

	currentMode, _ := tunneluser.GetAuthMode(username)

	// CLI mode if flags are provided
	if cmd.Flags().Changed("insecure-password") {
		if err := tunneluser.SetPassword(username, updatePassword); err != nil {
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

	if cmd.Flags().Changed("pubkey") {
		if err := tunneluser.SetupSSHKey(username, updatePubkey); err != nil {
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
	return runUpdateInteractive(username, currentMode)
}

func runUpdateInteractive(username string, currentMode tunneluser.AuthMode) error {
	fmt.Printf("\nUpdating user '%s' (current auth: %s)\n", username, currentMode)

	var choice string
	err := huh.NewSelect[string]().
		Title("What would you like to update?").
		Options(
			huh.NewOption("Change password (switch to password auth if needed)", "password"),
			huh.NewOption("Change SSH key (switch to key auth if needed)", "key"),
			huh.NewOption("Cancel", "cancel"),
		).
		Value(&choice).
		Run()
	if err != nil {
		return err
	}

	switch choice {
	case "password":
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

	case "key":
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
	}

	return nil
}
