package hostnet

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/tunnel"
)

type memoryJournal struct{ pending *Plan }

func (j *memoryJournal) Load() (*Plan, error) { return j.pending, nil }
func (j *memoryJournal) Save(plan Plan) error { j.pending = &plan; return nil }
func (j *memoryJournal) Delete() error        { j.pending = nil; return nil }

type simulatedHost struct {
	journal              *memoryJournal
	applied              []string
	steps                []string
	failApply, failClear bool
}

func (b *simulatedHost) Apply(ctx context.Context, plan Plan) error {
	if b.journal.pending == nil {
		return errors.New("missing intent")
	}
	b.steps = append(b.steps, "address", "route", "dns")
	b.applied = append(b.applied, "address", "route")
	if b.failApply {
		return errors.New("partial host failure")
	}
	b.applied = append(b.applied, "dns")
	return nil
}
func (b *simulatedHost) Clear(ctx context.Context, plan Plan) error {
	b.steps = append(b.steps, "clear_dns", "clear_route", "clear_address")
	if b.failClear {
		return errors.New("host cleanup failure")
	}
	b.applied = nil
	return nil
}

func samplePolicy() Policy {
	return Policy{Link: "testvpn", Table: 1050,
		AddressAllow: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/24")},
		RouteAllow:   []netip.Prefix{netip.MustParsePrefix("10.9.0.0/16")},
		DNSServers:   []netip.Addr{netip.MustParseAddr("10.9.0.53")}, DNSDomains: []string{"corp.test"}}
}

func generation() client.TunnelGeneration {
	cfg := tunnel.Configuration{IPv4: netip.MustParsePrefix("10.8.0.9/24")}
	cfg = cfg.WithNetworkOptions([]tunnel.Route{{Destination: netip.MustParsePrefix("10.9.0.0/24")}},
		tunnel.DNSConfig{Servers: []tunnel.DNSServer{{Addresses: []netip.AddrPort{netip.MustParseAddrPort("10.9.0.53:53")},
			ResolveDomains: []string{"corp.test"}}}})
	return client.TunnelGeneration{Number: 1, Control: client.ControlInfo{Tunnel: cfg}}
}

func TestPartialFailureAndRecovery(t *testing.T) {
	policy := samplePolicy()
	vpn := generation()
	store := new(memoryJournal)
	backend := &simulatedHost{journal: store, failApply: true, failClear: true}
	c, err := New(policy, backend, store)
	if err != nil {
		t.Fatal(err)
	}
	rollback, err := c.Configure(t.Context(), vpn)
	if rollback != nil || !errors.Is(err, ErrApply) || !errors.Is(err, ErrCleanup) || store.pending == nil {
		t.Fatalf("failed setup lost its journal: %v", err)
	}
	if _, err := c.Configure(t.Context(), vpn); !errors.Is(err, ErrPending) {
		t.Fatalf("pending recovery allowed reuse: %v", err)
	}
	if !slices.Equal(backend.steps, []string{"address", "route", "dns", "clear_dns", "clear_route", "clear_address"}) {
		t.Fatalf("steps = %v", backend.steps)
	}
	restarted, err := New(policy, backend, store)
	if err != nil {
		t.Fatal(err)
	}
	backend.failApply, backend.failClear = false, false
	if err := restarted.Recover(t.Context()); err != nil || store.pending != nil || len(backend.applied) != 0 {
		t.Fatalf("recovery failed: %v", err)
	}
	vpn.Control.Tunnel.IPv4 = netip.MustParsePrefix("192.0.2.1/24")
	if _, err := restarted.Configure(t.Context(), vpn); !errors.Is(err, ErrPolicy) || store.pending != nil {
		t.Fatalf("unauthorized plan reached backend: %v", err)
	}
	vpn = generation()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	rollback, err = restarted.Configure(ctx, vpn)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	rollback()
	rollback()
	if len(backend.applied) != 0 || restarted.CleanupError() != nil || store.pending != nil {
		t.Fatal("rollback did not clear its owned resources")
	}
}

type uncertainJournal struct {
	memoryJournal
	saveFails, deleteFails bool
}

func (j *uncertainJournal) Save(plan Plan) error {
	j.memoryJournal.Save(plan)
	if j.saveFails {
		return ErrJournal
	}
	return nil
}

func (j *uncertainJournal) Delete() error {
	j.memoryJournal.Delete()
	if j.deleteFails {
		return ErrJournal
	}
	return nil
}

func TestJournalDurabilityBlocksAdmission(t *testing.T) {
	for _, failSave := range []bool{false, true} {
		store := &uncertainJournal{saveFails: failSave, deleteFails: true}
		backend := &simulatedHost{journal: &store.memoryJournal}
		c, err := New(samplePolicy(), backend, store)
		if err != nil {
			t.Fatal(err)
		}
		rollback, err := c.Configure(t.Context(), generation())
		if failSave {
			if !errors.Is(err, ErrJournal) || rollback != nil || len(backend.steps) != 0 {
				t.Fatal("a failed journal save applied host resources")
			}
		} else {
			if err != nil || rollback == nil {
				t.Fatal(err)
			}
			rollback()
			rollback()
		}
		if !errors.Is(c.CleanupError(), ErrJournal) {
			t.Fatal("journal error was lost")
		}
		for range 2 {
			if _, err := c.Configure(t.Context(), generation()); !errors.Is(err, ErrPending) {
				t.Fatal("lease was admitted before journal durability was confirmed")
			}
			if err := c.Recover(t.Context()); !errors.Is(err, ErrJournal) || store.pending != nil {
				t.Fatal("a missing entry was treated as durable cleanup")
			}
		}
		if failSave && len(backend.steps) != 0 {
			t.Fatal("recovering an unapplied save touched host resources")
		}
		store.saveFails, store.deleteFails = false, false
		if err := c.Recover(t.Context()); err != nil {
			t.Fatal(err)
		}
		rollback, err = c.Configure(t.Context(), generation())
		if err != nil {
			t.Fatal(err)
		}
		rollback()
	}
}
