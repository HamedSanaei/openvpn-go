package observability

import (
	"context"
	"time"
)

// Phase identifies a protocol milestone without carrying any peer data.
type Phase string

const (
	PhaseTransport       Phase = "transport"
	PhaseResetACK        Phase = "reset_ack"
	PhaseTLS             Phase = "tls_verification"
	PhaseCredentials     Phase = "credentials"
	PhaseKeyMethodWrite  Phase = "key_method_write"
	PhaseKeyMethodRead   Phase = "key_method_read"
	PhaseKeyMethodFields Phase = "key_method_fields"
	PhasePush            Phase = "authenticated_push"
	PhaseKeyDerivation   Phase = "key_derivation"
	PhaseDataSetup       Phase = "data_channel_setup"
	PhaseRekeyDrain      Phase = "rekey_drain"
	PhaseRekeyInstall    Phase = "rekey_install"
)

// Progress is written only by the synchronous attempt owner.
type Progress struct {
	Phase   Phase
	Started time.Time
	Steps   uint8
}

type phaseKey struct{}

func WithProgress(ctx context.Context, p *Progress) context.Context {
	return context.WithValue(ctx, phaseKey{}, p)
}

func Enter(ctx context.Context, phase Phase) {
	if p, ok := ctx.Value(phaseKey{}).(*Progress); ok && p.Phase != phase {
		p.Phase, p.Started, p.Steps = phase, time.Now(), 0
	}
}

func Step(ctx context.Context) {
	if p, ok := ctx.Value(phaseKey{}).(*Progress); ok && p.Steps < 255 {
		p.Steps++
	}
}
