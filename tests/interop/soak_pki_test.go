//go:build linux

package interop_test

import (
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/testkit"
)

func init() {
	longLoadPKI = func(t *testing.T, duration time.Duration) testkit.PKI {
		return testkit.NewPKIForDuration(t, duration)
	}
}
