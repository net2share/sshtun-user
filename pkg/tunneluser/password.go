package tunneluser

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"
)

// GeneratePassword generates a secure random password (16 chars, alphanumeric).
func GeneratePassword() (string, error) {
	// Generate 18 bytes of random data
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Encode to base64 and remove non-alphanumeric characters
	encoded := base64.StdEncoding.EncodeToString(b)
	password := strings.NewReplacer("/", "", "+", "", "=", "").Replace(encoded)

	// Take first 16 characters
	if len(password) > 16 {
		password = password[:16]
	}

	return password, nil
}

// SetPassword sets the password for a user using chpasswd.
func SetPassword(username, password string) error {
	cmd := exec.Command("chpasswd")
	cmd.Stdin = strings.NewReader(fmt.Sprintf("%s:%s", username, password))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set password: %w", err)
	}
	fmt.Println("Password configured")
	return nil
}
