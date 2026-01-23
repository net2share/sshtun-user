package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/net2share/go-corelib/tui"
	"github.com/net2share/sshtun-user/pkg/tunneluser"
)

// promptUsername prompts for a username.
func promptUsername() string {
	fmt.Println()
	return tui.Prompt("Enter username for tunnel user")
}

// promptInteractive handles interactive mode for user creation.
// Returns authMode, password, publicKey, and noFail2ban.
func promptInteractive(username string, noFail2ban bool, fail2banInstalled bool) (tunneluser.AuthMode, string, string, bool) {
	authMode := promptAuthMode()

	var password, publicKey string
	if authMode == tunneluser.AuthModeKey {
		publicKey = promptPubkey(username)
	} else {
		password = promptPassword(username)
	}

	// Only prompt for fail2ban if:
	// - Not explicitly disabled via --no-fail2ban
	// - fail2ban is NOT already installed (if installed, we'll just use it)
	if !noFail2ban && !fail2banInstalled {
		noFail2ban = !promptFail2ban()
	}

	return authMode, password, publicKey, noFail2ban
}

func promptAuthMode() tunneluser.AuthMode {
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

func promptPassword(username string) string {
	fmt.Println()
	fmt.Printf("Enter password for '%s' (leave empty to auto-generate):\n", username)

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Password: ")
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)

	if password == "" {
		generated, err := tunneluser.GeneratePassword()
		if err != nil {
			tui.PrintError("Failed to generate password: " + err.Error())
			os.Exit(1)
		}
		password = generated
		fmt.Println()
		fmt.Println("============================================")
		fmt.Println("  GENERATED PASSWORD (save this now!):")
		fmt.Printf("  %s\n", password)
		fmt.Println("============================================")
		fmt.Println()
	}

	return password
}

func promptPubkey(username string) string {
	fmt.Println()
	fmt.Printf("Enter the user's SSH public key for '%s':\n", username)
	fmt.Println("(from their ~/.ssh/id_ed25519.pub or similar)")

	key := tui.Prompt("Public key")
	if key == "" {
		tui.PrintError("Public key is required for key-based auth")
		os.Exit(1)
	}

	if err := tunneluser.ValidatePublicKey(key); err != nil {
		tui.PrintError("Invalid public key format")
		os.Exit(1)
	}

	return key
}

func promptFail2ban() bool {
	fmt.Println()
	fmt.Println("Enable fail2ban brute-force protection?")
	fmt.Println("  - Bans IPs after 5 failed login attempts")
	fmt.Println("  - Recommended for password authentication")
	fmt.Println()

	return tui.Confirm("Enable fail2ban?", true)
}
