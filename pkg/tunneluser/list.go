package tunneluser

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
)

// UserInfo represents a tunnel user with their authentication mode.
type UserInfo struct {
	Username string
	AuthMode AuthMode
}

// List returns all users that are members of tunnel groups.
func List() ([]UserInfo, error) {
	var users []UserInfo
	seen := make(map[string]bool)

	// Get members of both tunnel groups (supplementary membership)
	passwordUsers, err := getGroupMembers(GroupPasswordAuth)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to get password auth users: %w", err)
	}

	keyUsers, err := getGroupMembers(GroupKeyAuth)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to get key auth users: %w", err)
	}

	// Also get users whose primary group is a tunnel group
	primaryPasswordUsers, _ := getUsersWithPrimaryGroup(GroupPasswordAuth)
	primaryKeyUsers, _ := getUsersWithPrimaryGroup(GroupKeyAuth)

	// Merge supplementary and primary group members
	passwordUsers = append(passwordUsers, primaryPasswordUsers...)
	keyUsers = append(keyUsers, primaryKeyUsers...)

	// Add password auth users
	for _, username := range passwordUsers {
		if seen[username] {
			continue
		}
		seen[username] = true
		users = append(users, UserInfo{
			Username: username,
			AuthMode: AuthModePassword,
		})
	}

	// Add key auth users
	for _, username := range keyUsers {
		if seen[username] {
			continue
		}
		seen[username] = true
		users = append(users, UserInfo{
			Username: username,
			AuthMode: AuthModeKey,
		})
	}

	return users, nil
}

// GetAuthMode returns the authentication mode for a specific user.
// Returns an error if the user is not in any tunnel group.
func GetAuthMode(username string) (AuthMode, error) {
	inPassword, _ := isInGroup(username, GroupPasswordAuth)
	if inPassword {
		return AuthModePassword, nil
	}

	inKey, _ := isInGroup(username, GroupKeyAuth)
	if inKey {
		return AuthModeKey, nil
	}

	return "", fmt.Errorf("user '%s' is not a tunnel user", username)
}

// IsTunnelUser checks if a user is a tunnel user (member of any tunnel group).
func IsTunnelUser(username string) bool {
	_, err := GetAuthMode(username)
	return err == nil
}

// Delete removes a tunnel user and cleans up all related files.
// This includes:
// - Removing user from tunnel groups
// - Deleting the system user
// - Removing SSH key file from /etc/ssh/authorized_keys.d/<username>
// - Removing from cron.deny and at.deny
func Delete(username string) error {
	// Verify user is a tunnel user
	if !IsTunnelUser(username) {
		return fmt.Errorf("user '%s' is not a tunnel user", username)
	}

	// Remove from tunnel groups
	for _, group := range []string{GroupPasswordAuth, GroupKeyAuth} {
		exec.Command("gpasswd", "-d", username, group).Run()
	}

	// Delete system user
	cmd := exec.Command("userdel", username)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	// Remove SSH key file if it exists
	authKeysFile := filepath.Join(AuthorizedKeysDir, username)
	if _, err := os.Stat(authKeysFile); err == nil {
		if err := os.Remove(authKeysFile); err != nil {
			return fmt.Errorf("failed to remove SSH key file: %w", err)
		}
	}

	// Remove from deny files
	removeFromDenyFiles(username)

	return nil
}

// getGroupMembers returns all members of a group by parsing /etc/group.
// This only returns supplementary group members, not users with this as primary group.
func getGroupMembers(groupName string) ([]string, error) {
	file, err := os.Open("/etc/group")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// Format: group_name:password:GID:user_list
		parts := strings.Split(line, ":")
		if len(parts) < 4 {
			continue
		}

		if parts[0] == groupName {
			userList := parts[3]
			if userList == "" {
				return []string{}, nil
			}
			return strings.Split(userList, ","), nil
		}
	}

	return []string{}, scanner.Err()
}

// getUsersWithPrimaryGroup returns all users whose primary group is the specified group.
func getUsersWithPrimaryGroup(groupName string) ([]string, error) {
	// Get the GID of the group
	g, err := user.LookupGroup(groupName)
	if err != nil {
		return nil, err
	}

	// Parse /etc/passwd to find users with this GID
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var users []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// Format: username:password:UID:GID:GECOS:home:shell
		parts := strings.Split(line, ":")
		if len(parts) < 4 {
			continue
		}

		if parts[3] == g.Gid {
			users = append(users, parts[0])
		}
	}

	return users, scanner.Err()
}

// isInGroup checks if a user is a member of a specific group.
// This checks both supplementary group membership and primary group.
func isInGroup(username, groupName string) (bool, error) {
	// Check supplementary group membership
	members, err := getGroupMembers(groupName)
	if err == nil {
		for _, member := range members {
			if member == username {
				return true, nil
			}
		}
	}

	// Check if it's the user's primary group
	isPrimary, err := isPrimaryGroup(username, groupName)
	if err == nil && isPrimary {
		return true, nil
	}

	return false, nil
}

// isPrimaryGroup checks if a group is the user's primary group.
func isPrimaryGroup(username, groupName string) (bool, error) {
	// Get user info
	u, err := user.Lookup(username)
	if err != nil {
		return false, err
	}

	// Get group info
	g, err := user.LookupGroup(groupName)
	if err != nil {
		return false, err
	}

	return u.Gid == g.Gid, nil
}

// removeFromDenyFiles removes a username from cron.deny and at.deny files.
func removeFromDenyFiles(username string) {
	for _, denyFile := range []string{"/etc/cron.deny", "/etc/at.deny"} {
		data, err := os.ReadFile(denyFile)
		if err != nil {
			continue
		}

		lines := splitLines(string(data))
		var newLines []string
		for _, line := range lines {
			if line != username {
				newLines = append(newLines, line)
			}
		}

		newContent := strings.Join(newLines, "\n")
		if len(newLines) > 0 && !strings.HasSuffix(newContent, "\n") {
			newContent += "\n"
		}

		os.WriteFile(denyFile, []byte(newContent), 0644)
	}
}
