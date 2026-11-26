package tlscontrol

import (
	"errors"
	"strings"
	"testing"
)

func TestAuthenticatedDisconnectCommands(t *testing.T) {
	for _, tc := range []struct {
		message string
		want    error
	}{
		{"RESTART", ErrPeerRestart},
		{"RESTART,private-marker", ErrPeerRestart},
		{"RESTART,[N]private-marker", ErrPeerRestartSame},
		{"RESTART,[P]private-marker", ErrAuth},
		{"RESTART,[Nprivate-marker", ErrNegotiation},
		{"RESTART,[X]private-marker", ErrNegotiation},
		{"HALT,private-marker", ErrPeerStopped},
		{"EXIT", ErrPeerStopped},
		{"AUTH_FAILED,TEMP:private-marker", ErrAuth},
	} {
		err := unexpectedCommand([]byte(tc.message))
		if !errors.Is(err, tc.want) || strings.Contains(err.Error(), "private-marker") {
			t.Fatalf("unexpected disconnect classification: %v, want %v", err, tc.want)
		}
	}
}
