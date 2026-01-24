package cli

import (
	"fmt"

	"github.com/net2share/go-corelib/tui"
	"github.com/net2share/sshtun-user/pkg/tunneluser"
)

// ListUsers lists all tunnel users.
func ListUsers() error {
	users, err := tunneluser.List()
	if err != nil {
		return fmt.Errorf("failed to list users: %w", err)
	}

	if len(users) == 0 {
		fmt.Println("No tunnel users found.")
		return nil
	}

	fmt.Println("Tunnel users:")
	for _, user := range users {
		fmt.Printf("  %s (%s)\n", user.Username, user.AuthMode)
	}

	return nil
}

// ListUsersBox displays all tunnel users in a box format.
func ListUsersBox() {
	fmt.Println()
	users, err := tunneluser.List()
	if err != nil {
		tui.PrintError("Failed to list users: " + err.Error())
		return
	}

	if len(users) == 0 {
		tui.PrintInfo("No tunnel users found.")
		return
	}

	lines := make([]string, len(users))
	for i, user := range users {
		lines[i] = fmt.Sprintf("%s (%s auth)", user.Username, user.AuthMode)
	}

	tui.PrintBox("Tunnel Users", lines)
}
