// Package platform connects native VPN lifecycle events to session leases.
package platform

import (
	"context"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/integrations/sessions"
)

// Run holds a session lease until native revocation or a network change.
// The application's DeviceFactory bridges native IP packets and installs
// generation settings, while changes signals that new sockets are needed.
// A closed change channel disables further notifications. Calls into native
// code must honor their contexts so teardown can finish. Keep config
// immutable while Run may use it to start new leases. The returned status is
// from the last completed lease, including a lease joined before readmission.
func Run(ctx context.Context, manager *sessions.Manager, id string, config client.Config,
	open sessions.DeviceFactory, changes <-chan struct{}) (sessions.Status, error) {
	if manager == nil {
		return sessions.Status{}, sessions.ErrConfig
	}
	var previous sessions.Status
	for {
		if err := ctx.Err(); err != nil {
			return previous, err
		}
		lease, err := manager.Start(ctx, id, config, open)
		if err != nil {
			if cause := ctx.Err(); cause != nil {
				return previous, cause
			}
			return previous, err
		}
		restart := false
		for !restart {
			select {
			case <-lease.Done():
				status, _ := lease.Wait(context.Background())
				return status, ctx.Err()
			case <-ctx.Done():
				lease.Stop()
				status, _ := lease.Wait(context.Background())
				return status, ctx.Err()
			case _, ok := <-changes:
				if !ok {
					changes = nil
					continue
				}
				lease.Stop()
				previous, _ = lease.Wait(context.Background())
				restart = true
			}
		}
	}
}
