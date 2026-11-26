//go:build linux

package hostnet

import (
	"net/netip"
	"os"
	"os/exec"
	"testing"
)

func TestFileJournalSurvivesControllerExit(t *testing.T) {
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	first, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := OpenJournal(path); err == nil {
		other.Close()
		t.Fatal("journal lock was shared")
	}
	plan, err := samplePolicy().plan(generation().Control.Tunnel)
	if err != nil || first.Save(plan) != nil {
		first.Close()
		t.Fatal("could not save lease")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if got, err := second.Load(); err != nil || got == nil || got.Link != plan.Link || len(got.Routes) != 1 {
		t.Fatalf("recovered journal: %+v, %v", got, err)
	}
	if err := second.Delete(); err != nil {
		t.Fatal(err)
	}
	if got, err := second.Load(); err != nil || got != nil {
		t.Fatalf("delete: %v", err)
	}
}

func TestLinuxLeaseInIsolatedNamespace(t *testing.T) {
	if os.Getenv("OPENVPN_TEST_HOSTNET") != "1" {
		t.Skip("requires an explicitly isolated network namespace with CAP_NET_ADMIN")
	}
	ctx := t.Context()
	ip := func(args ...string) {
		t.Helper()
		if out, err := exec.CommandContext(ctx, ipCommand, args...).CombinedOutput(); err != nil {
			t.Fatalf("isolated ip operation failed: %v %s", err, out)
		}
	}
	ip("link", "add", "testvpn", "type", "dummy")
	t.Cleanup(func() { exec.Command(ipCommand, "link", "delete", "testvpn").Run() })
	ip("link", "set", "testvpn", "up")
	backend, err := LinuxBackend("testvpn", 1050, false)
	if err != nil {
		t.Fatal(err)
	}
	plan := Plan{Link: "testvpn", Table: 1050,
		Addresses: []netip.Prefix{netip.MustParsePrefix("10.8.0.9/24")},
		Routes:    []netip.Prefix{netip.MustParsePrefix("10.9.0.0/24")}}
	// An already absent table is a valid recovery state.
	if err := backend.Clear(ctx, plan); err != nil {
		t.Fatal(err)
	}
	if err := backend.Apply(ctx, plan); err != nil {
		t.Fatal(err)
	}
	if backend.(linuxBackend).routeAbsent(ctx, plan.Routes[0]) {
		t.Fatal("route absent after commit")
	}
	for range 2 {
		if err := backend.Clear(ctx, plan); err != nil {
			t.Fatal(err)
		}
	}
	if !backend.(linuxBackend).routeAbsent(ctx, plan.Routes[0]) {
		t.Fatal("owned route leaked")
	}
}
