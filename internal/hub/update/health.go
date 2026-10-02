package update

import (
	"context"
	"fmt"

	"github.com/phabioo/nexara/internal/hub/setup"
)

// AdminHealth returns the helper's health probe: it asks the running hub for
// its version over the admin socket (setup.CmdVersion).
func AdminHealth(socket string) func(ctx context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		resp, err := setup.AdminCall(socket, setup.CmdVersion)
		if err != nil {
			return "", err
		}
		if !resp.OK || resp.Version == "" {
			return "", fmt.Errorf("hub answered without a version: %s", resp.Message)
		}
		return resp.Version, nil
	}
}
