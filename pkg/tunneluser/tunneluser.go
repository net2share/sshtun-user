// Package tunneluser provides functions for creating and managing SSH tunnel users.
package tunneluser

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
)

// AuthMode represents the authentication method for a tunnel user.
type AuthMode string

const (
	AuthModePassword AuthMode = "password"
	AuthModeKey      AuthMode = "key"
)

// Group names for tunnel users.
const (
	GroupPasswordAuth = "sshtunnel-password"
	GroupKeyAuth      = "sshtunnel-key"
)

// Config holds the configuration for creating a tunnel user.
type Config struct {
	Username  string
	AuthMode  AuthMode
	Password  string // For password auth
	PublicKey string // For key auth
}

// EnsureGroups creates the tunnel user groups if they don't exist.
func EnsureGroups() error {
	for _, group := range []string{GroupPasswordAuth, GroupKeyAuth} {
		if _, err := user.LookupGroup(group); err != nil {
			cmd := exec.Command("groupadd", group)
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to create group %s: %w", group, err)
			}
		}
	}
	return nil
}

// Exists checks if a user already exists.
func Exists(username string) bool {
	_, err := user.Lookup(username)
	return err == nil
}

// Create creates a new tunnel user with the specified configuration.
func Create(cfg *Config) error {
	if cfg.Username == "" {
		return fmt.Errorf("username is required")
	}

	// Ensure groups exist
	if err := EnsureGroups(); err != nil {
		return err
	}

	// Determine which group to use
	userGroup := GroupPasswordAuth
	if cfg.AuthMode == AuthModeKey {
		userGroup = GroupKeyAuth
	}

	if Exists(cfg.Username) {
		// User exists, update group membership
		fmt.Printf("User '%s' already exists, updating group to %s...\n", cfg.Username, userGroup)

		// Remove from old tunnel groups
		for _, g := range []string{GroupPasswordAuth, GroupKeyAuth} {
			exec.Command("gpasswd", "-d", cfg.Username, g).Run()
		}

		// Add to new group
		cmd := exec.Command("usermod", "-aG", userGroup, cfg.Username)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to update user group: %w", err)
		}
	} else {
		// Create new user
		cmd := exec.Command("useradd",
			"--system",
			"--shell", "/usr/sbin/nologin",
			"--no-create-home",
			"--home-dir", "/nonexistent",
			"--gid", userGroup,
			"--comment", fmt.Sprintf("SSH tunnel only (%s)", cfg.AuthMode),
			cfg.Username,
		)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}
		fmt.Printf("User '%s' created\n", cfg.Username)
	}

	// Configure authentication
	if cfg.AuthMode == AuthModeKey {
		if err := SetupSSHKey(cfg.Username, cfg.PublicKey); err != nil {
			return err
		}
	} else {
		if err := SetPassword(cfg.Username, cfg.Password); err != nil {
			return err
		}
	}

	// Block cron/at access
	blockScheduledTasks(cfg.Username)

	fmt.Printf("\nUser '%s' configured for tunnel-only access (%s auth)\n", cfg.Username, cfg.AuthMode)
	return nil
}

// blockScheduledTasks adds the user to cron.deny and at.deny.
func blockScheduledTasks(username string) {
	for _, denyFile := range []string{"/etc/cron.deny", "/etc/at.deny"} {
		// Try to create file if it doesn't exist
		if _, err := os.Stat(denyFile); os.IsNotExist(err) {
			if f, err := os.Create(denyFile); err == nil {
				f.Close()
			}
		}

		// Check if user is already in deny file
		data, err := os.ReadFile(denyFile)
		if err != nil {
			continue
		}

		// Check if username already exists in file
		found := false
		for _, line := range splitLines(string(data)) {
			if line == username {
				found = true
				break
			}
		}

		if !found {
			f, err := os.OpenFile(denyFile, os.O_APPEND|os.O_WRONLY, 0644)
			if err == nil {
				f.WriteString(username + "\n")
				f.Close()
			}
		}
	}
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
