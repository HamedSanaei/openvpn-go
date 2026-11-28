// Package cleanup classifies the result of closing owned resources.
package cleanup

import (
	"errors"
	"net"
)

// Failed reports whether any close result is independently uncertain.
// An already-closed result is benign. In a join all causes must be benign.
func Failed(err error) bool {
	for err != nil {
		if joined, ok := err.(interface{ Unwrap() []error }); ok {
			for _, child := range joined.Unwrap() {
				if Failed(child) {
					return true
				}
			}
			return false
		}
		if nested := errors.Unwrap(err); nested != nil {
			err = nested
			continue
		}
		return !errors.Is(err, net.ErrClosed)
	}
	return false
}
