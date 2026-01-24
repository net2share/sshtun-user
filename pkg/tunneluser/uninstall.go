package tunneluser

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// DeleteAllUsers deletes all tunnel users (members of tunnel groups).
// Returns the list of deleted usernames and any error.
func DeleteAllUsers() ([]string, error) {
	users, err := List()
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	if len(users) == 0 {
		return nil, nil
	}

	var deleted []string
	var errors []string

	for _, user := range users {
		if err := Delete(user.Username); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", user.Username, err))
		} else {
			deleted = append(deleted, user.Username)
		}
	}

	if len(errors) > 0 {
		return deleted, fmt.Errorf("some users could not be deleted: %v", errors)
	}

	return deleted, nil
}

// GroupsHaveUsers checks if the tunnel groups have any members.
// This checks both supplementary group membership and users with primary group.
func GroupsHaveUsers() (bool, error) {
	for _, group := range []string{GroupPasswordAuth, GroupKeyAuth} {
		// Check supplementary group members
		members, err := getGroupMembers(group)
		if err == nil && len(members) > 0 {
			return true, nil
		}

		// Check users with this as primary group
		primaryUsers, err := getUsersWithPrimaryGroup(group)
		if err == nil && len(primaryUsers) > 0 {
			return true, nil
		}
	}
	return false, nil
}

// DeleteGroups deletes the tunnel groups.
// Returns error if groups still have members.
func DeleteGroups() error {
	hasUsers, err := GroupsHaveUsers()
	if err != nil {
		return err
	}
	if hasUsers {
		return fmt.Errorf("cannot delete groups: tunnel users still exist. Delete users first")
	}

	for _, group := range []string{GroupPasswordAuth, GroupKeyAuth} {
		// Check if group exists before trying to delete
		if _, err := exec.Command("getent", "group", group).Output(); err != nil {
			continue // Group doesn't exist
		}

		cmd := exec.Command("groupdel", group)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to delete group %s: %w", group, err)
		}
	}

	return nil
}

// CleanupAuthorizedKeysDir removes the authorized_keys.d directory if empty,
// or removes only the files for deleted users.
func CleanupAuthorizedKeysDir() error {
	// Check if directory exists
	if _, err := os.Stat(AuthorizedKeysDir); os.IsNotExist(err) {
		return nil
	}

	// Read directory contents
	entries, err := os.ReadDir(AuthorizedKeysDir)
	if err != nil {
		return fmt.Errorf("failed to read authorized_keys.d: %w", err)
	}

	// If empty, remove the directory
	if len(entries) == 0 {
		return os.Remove(AuthorizedKeysDir)
	}

	// Otherwise, just remove files for users that no longer exist
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		username := entry.Name()
		if !Exists(username) {
			os.Remove(filepath.Join(AuthorizedKeysDir, username))
		}
	}

	// Check again if directory is now empty
	entries, _ = os.ReadDir(AuthorizedKeysDir)
	if len(entries) == 0 {
		return os.Remove(AuthorizedKeysDir)
	}

	return nil
}

// CleanupDenyFiles removes all tunnel user entries from cron.deny and at.deny.
// Since we can't know which entries we added, this removes entries for users
// that no longer exist on the system.
func CleanupDenyFiles() {
	for _, denyFile := range []string{"/etc/cron.deny", "/etc/at.deny"} {
		data, err := os.ReadFile(denyFile)
		if err != nil {
			continue
		}

		lines := splitLines(string(data))
		var newLines []string
		for _, line := range lines {
			// Keep the line if it's empty or the user still exists
			if line == "" || Exists(line) {
				newLines = append(newLines, line)
			}
		}

		// Only write back if we removed something
		if len(newLines) < len(lines) {
			content := ""
			for _, line := range newLines {
				if line != "" {
					content += line + "\n"
				}
			}
			os.WriteFile(denyFile, []byte(content), 0644)
		}
	}
}
