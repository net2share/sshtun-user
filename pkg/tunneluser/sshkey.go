package tunneluser

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
)

const (
	// AuthorizedKeysDir is where SSH keys are stored for tunnel users.
	AuthorizedKeysDir = "/etc/ssh/authorized_keys.d"
)

// ValidatePublicKey validates an SSH public key format.
func ValidatePublicKey(key string) error {
	// Match common SSH public key formats
	pattern := `^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp\d+|ssh-dss) `
	matched, err := regexp.MatchString(pattern, key)
	if err != nil {
		return fmt.Errorf("failed to validate key: %w", err)
	}
	if !matched {
		return fmt.Errorf("invalid public key format")
	}
	return nil
}

// SetupSSHKey configures an SSH public key for a tunnel user.
func SetupSSHKey(username, publicKey string) error {
	if err := ValidatePublicKey(publicKey); err != nil {
		return err
	}

	// Create authorized_keys.d directory
	if err := os.MkdirAll(AuthorizedKeysDir, 0755); err != nil {
		return fmt.Errorf("failed to create authorized_keys.d: %w", err)
	}

	authKeysFile := filepath.Join(AuthorizedKeysDir, username)

	// Write the public key with restrictions
	// "restrict" enables all restrictions, "port-forwarding" re-enables just that
	content := fmt.Sprintf("restrict,port-forwarding %s\n", publicKey)
	if err := os.WriteFile(authKeysFile, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write authorized_keys file: %w", err)
	}

	// Set ownership to root
	if err := exec.Command("chown", "root:root", authKeysFile).Run(); err != nil {
		return fmt.Errorf("failed to set ownership: %w", err)
	}

	fmt.Printf("SSH public key configured at: %s\n", authKeysFile)
	return nil
}
