package cleanup

import (
	"errors"
	"fmt"
	"net"
	"testing"
)

func TestIndependentCleanupInJoinedErrors(t *testing.T) {
	independent := errors.New("synthetic cleanup error")
	wrapped := fmt.Errorf("socket: %w", net.ErrClosed)
	for _, test := range []struct {
		name string
		err  error
		fail bool
	}{
		{"success", nil, false},
		{"closed", net.ErrClosed, false},
		{"wrapped_closed", wrapped, false},
		{"all_closed", errors.Join(wrapped, net.ErrClosed), false},
		{"failure", independent, true},
		{"benign_first", errors.Join(net.ErrClosed, independent), true},
		{"failure_first", errors.Join(independent, net.ErrClosed), true},
		{"nested", errors.Join(net.ErrClosed, fmt.Errorf("wrapped join: %w",
			errors.Join(wrapped, errors.Join(independent, net.ErrClosed)))), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if Failed(test.err) != test.fail {
				t.Fatalf("unexpected cleanup classification: %v", test.err)
			}
		})
	}
}
