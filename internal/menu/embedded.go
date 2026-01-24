package menu

import (
	"github.com/net2share/go-corelib/osdetect"
)

// RunEmbedded shows the user management menu in embedded mode (for dnstm).
func RunEmbedded() error {
	osInfo, _ := osdetect.Detect()
	return runMenuLoop(osInfo, false)
}
