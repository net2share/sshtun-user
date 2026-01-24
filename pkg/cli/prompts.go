// Package cli provides the exported interactive CLI for sshtun-user.
package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/net2share/go-corelib/tui"
	"github.com/net2share/sshtun-user/pkg/tunneluser"
)

// PromptUsername prompts for a username.
// Returns the username or an error if cancelled.
func PromptUsername() (string, error) {
	fmt.Println()
	username := tui.Prompt("Enter username for tunnel user")
	if username == "" {
		return "", fmt.Errorf("username required")
	}
	return username, nil
}

// PromptAuthMode prompts the user to select an authentication method.
func PromptAuthMode() tunneluser.AuthMode {
	fmt.Println()
	fmt.Println("Select authentication method:")
	fmt.Println("  1) Password (default) - simpler, suitable for shared/semi-public access")
	fmt.Println("  2) SSH Key - more secure, user must provide their public key")
	fmt.Println()

	choice := tui.PromptWithDefault("Enter choice", "1")
	switch choice {
	case "2":
		return tunneluser.AuthModeKey
	default:
		return tunneluser.AuthModePassword
	}
}

// PromptPassword prompts for a password or generates one.
// Returns the password (entered or generated), or an error if generation fails.
func PromptPassword(username string) (string, error) {
	fmt.Println()
	fmt.Printf("Enter password for '%s' (leave empty to auto-generate):\n", username)

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Password: ")
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)

	if password == "" {
		generated, err := tunneluser.GeneratePassword()
		if err != nil {
			return "", fmt.Errorf("failed to generate password: %w", err)
		}
		password = generated
		fmt.Println()
		fmt.Println("============================================")
		fmt.Println("  GENERATED PASSWORD (save this now!):")
		fmt.Printf("  %s\n", password)
		fmt.Println("============================================")
		fmt.Println()
	}

	return password, nil
}

// PromptPubkey prompts for an SSH public key with validation.
// Returns the public key or an error if empty or invalid.
func PromptPubkey(username string) (string, error) {
	fmt.Println()
	fmt.Printf("Enter the user's SSH public key for '%s':\n", username)
	fmt.Println("(from their ~/.ssh/id_ed25519.pub or similar)")

	key := tui.Prompt("Public key")
	if key == "" {
		return "", fmt.Errorf("public key is required for key-based auth")
	}

	if err := tunneluser.ValidatePublicKey(key); err != nil {
		return "", fmt.Errorf("invalid public key format: %w", err)
	}

	return key, nil
}

// PromptFail2ban prompts the user to enable fail2ban.
func PromptFail2ban() bool {
	fmt.Println()
	fmt.Println("Enable fail2ban brute-force protection?")
	fmt.Println("  - Bans IPs after 5 failed login attempts")
	fmt.Println("  - Recommended for password authentication")
	fmt.Println()

	return tui.Confirm("Enable fail2ban?", true)
}

// PromptInteractive handles interactive mode for user creation.
// Returns authMode, password, publicKey, noFail2ban, and an error if prompting fails.
func PromptInteractive(username string, noFail2ban bool, fail2banInstalled bool) (tunneluser.AuthMode, string, string, bool, error) {
	authMode := PromptAuthMode()

	var password, publicKey string
	var err error

	if authMode == tunneluser.AuthModeKey {
		publicKey, err = PromptPubkey(username)
		if err != nil {
			return authMode, "", "", noFail2ban, err
		}
	} else {
		password, err = PromptPassword(username)
		if err != nil {
			return authMode, "", "", noFail2ban, err
		}
	}

	// Only prompt for fail2ban if:
	// - Not explicitly disabled via --no-fail2ban
	// - fail2ban is NOT already installed (if installed, we'll just use it)
	if !noFail2ban && !fail2banInstalled {
		noFail2ban = !PromptFail2ban()
	}

	return authMode, password, publicKey, noFail2ban, nil
}
