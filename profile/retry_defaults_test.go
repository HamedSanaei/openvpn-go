package profile

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/transport"
)

type profileLookup func(context.Context, string, string) ([]netip.Addr, error)

func (lookup profileLookup) LookupNetIP(ctx context.Context, family, host string) ([]netip.Addr, error) {
	return lookup(ctx, family, host)
}

func TestProfileRetryDefaults(t *testing.T) {
	base := testProfile + inlinePKI(testkit.NewPKI(t))
	for _, tc := range []struct {
		extra                     string
		attempts                  int
		initial, ceiling, resolve time.Duration
	}{
		{"", client.UnlimitedAttempts, time.Second, 300 * time.Second, client.ResolveUntilDialDeadline},
		{"connect-retry 7\n", client.UnlimitedAttempts, 7 * time.Second, 300 * time.Second, client.ResolveUntilDialDeadline},
		{"remote second.example.test\nconnect-retry-max 3\nconnect-retry 7 20\nresolv-retry 0\n", 6, 7 * time.Second, 20 * time.Second, 0},
	} {
		cfg, _, err := Parse(strings.NewReader(base+tc.extra), Options{})
		if err != nil || cfg.Retry.MaxAttempts != tc.attempts || cfg.Retry.InitialBackoff != tc.initial ||
			cfg.Retry.MaxBackoff != tc.ceiling || cfg.ResolveRetry != tc.resolve {
			t.Fatalf("retry configuration = %+v, DNS = %v, error = %v", cfg.Retry, cfg.ResolveRetry, err)
		}
	}
	for _, explicit := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			input := base + "connect-retry-max 1\n"
			if explicit {
				input += "resolv-retry 0\n"
			}
			cfg, _, err := Parse(strings.NewReader(input), Options{})
			if err != nil {
				t.Fatal(err)
			}
			var lookups, dials int
			cfg.Resolver = profileLookup(func(context.Context, string, string) ([]netip.Addr, error) {
				lookups++
				if lookups == 1 {
					return nil, errors.New("transient resolver result")
				}
				return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
			})
			cfg.Dialer = testkit.DialerFunc(func(context.Context, string, string) (transport.PacketConn, error) {
				dials++
				return nil, errors.New("synthetic transport loss")
			})
			c, err := client.New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			var failure *client.Error
			if err := c.Connect(t.Context()); !errors.As(err, &failure) || failure.Code != client.CodeNetwork {
				t.Fatalf("unexpected dial result: %v", err)
			}
			want := 1
			if !explicit {
				want = 2
			}
			if lookups != want || dials != want-1 {
				t.Fatalf("lookups=%d dials=%d, want %d/%d", lookups, dials, want, want-1)
			}
		})
	}
	synctest.Test(t, func(t *testing.T) {
		cfg, _, err := Parse(strings.NewReader(strings.Replace(base, "vpn.example.test", "192.0.2.10", 1)), Options{})
		if err != nil {
			t.Fatal(err)
		}
		var dials int
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		cfg.Dialer = testkit.DialerFunc(func(context.Context, string, string) (transport.PacketConn, error) {
			dials++
			if dials == 5 {
				cancel()
			}
			return nil, errors.New("synthetic loss")
		})
		c, err := client.New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		var failure *client.Error
		if err := c.Connect(ctx); !errors.As(err, &failure) || failure.Code != client.CodeCanceled || dials != 5 {
			t.Fatalf("omitted attempt limit: %v after %d dials", err, dials)
		}
	})
}
