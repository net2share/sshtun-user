package cmd

import (
	"fmt"

	"github.com/net2share/go-corelib/osdetect"
	"github.com/net2share/go-corelib/tui"
	"github.com/net2share/sshtun-user/pkg/sshdconfig"
	"github.com/net2share/sshtun-user/pkg/tunneluser"
	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all tunnel users",
	RunE:  runList,
}

func runList(cmd *cobra.Command, args []string) error {
	if err := osdetect.RequireRoot(); err != nil {
		return err
	}

	if !sshdconfig.IsConfigured() {
		return fmt.Errorf("sshd not configured. Run 'sshtun-user configure' first")
	}

	users, err := tunneluser.List()
	if err != nil {
		return fmt.Errorf("failed to list users: %w", err)
	}

	items := make([]string, len(users))
	for i, user := range users {
		items[i] = fmt.Sprintf("%s (%s auth)", user.Username, user.AuthMode)
	}

	// Set app info for fullscreen footer
	tui.SetAppInfo("sshtun-user", Version, BuildTime)

	return tui.ShowList(tui.ListConfig{
		Title:     "Tunnel Users",
		Items:     items,
		EmptyText: "No tunnel users found.",
	})
}
