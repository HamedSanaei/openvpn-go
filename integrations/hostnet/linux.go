//go:build linux

package hostnet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os/exec"
	"strconv"
)

const ipCommand = "/usr/sbin/ip"
const resolvedCommand = "/usr/bin/resolvectl"
const routeProtocol = "222"

type linuxBackend struct {
	link     string
	table    uint32
	resolved bool
}

// LinuxBackend manages an exclusively provisioned link and routing table
// using iproute2. resolved enables explicitly allowlisted per-link DNS.
func LinuxBackend(link string, table uint32, resolved bool) (Backend, error) {
	if !validScope(link, table) {
		return nil, ErrPolicy
	}
	return linuxBackend{link: link, table: table, resolved: resolved}, nil
}

func (b linuxBackend) acceptsPolicy(policy Policy) bool {
	return b.link == policy.Link && b.table == policy.Table &&
		(b.resolved || len(policy.DNSServers) == 0 && len(policy.DNSDomains) == 0)
}

func (b linuxBackend) authorized(plan Plan) bool {
	return (b.resolved || len(plan.DNSServers) == 0) &&
		(Policy{Link: b.link, Table: b.table,
			AddressAllow: []netip.Prefix{netip.PrefixFrom(netip.IPv4Unspecified(), 0), netip.PrefixFrom(netip.IPv6Unspecified(), 0)},
			RouteAllow:   []netip.Prefix{netip.PrefixFrom(netip.IPv4Unspecified(), 0), netip.PrefixFrom(netip.IPv6Unspecified(), 0)},
			DNSServers:   plan.DNSServers, DNSDomains: plan.DNSDomains}).authorizes(plan) &&
		validDNS(plan)
}

func validDNS(plan Plan) bool {
	for _, server := range plan.DNSServers {
		if !validServer(server) {
			return false
		}
	}
	for _, domain := range plan.DNSDomains {
		if !validDomain(domain) {
			return false
		}
	}
	return true
}

func (b linuxBackend) Apply(ctx context.Context, plan Plan) error {
	if !b.authorized(plan) {
		return ErrPolicy
	}
	for _, address := range plan.Addresses {
		args := []string{family(address), "address", "add", address.String(), "dev", b.link, "noprefixroute"}
		if address.Addr().Is6() {
			args = append(args, "nodad")
		}
		if err := command(ctx, ipCommand, args...); err != nil {
			return ErrApply
		}
	}
	for _, route := range plan.Routes {
		if err := command(ctx, ipCommand, family(route), "route", "add", route.String(), "dev", b.link, "table", strconv.FormatUint(uint64(b.table), 10), "proto", routeProtocol); err != nil {
			return ErrApply
		}
	}
	if len(plan.DNSServers) == 0 {
		return nil
	}
	domains := []string{"domain", b.link}
	for _, domain := range plan.DNSDomains {
		domains = append(domains, "~"+domain)
	}
	servers := []string{"dns", b.link}
	for _, server := range plan.DNSServers {
		servers = append(servers, server.String())
	}
	for _, args := range [][]string{{"default-route", b.link, "no"}, domains, servers} {
		if err := command(ctx, resolvedCommand, args...); err != nil {
			return ErrApply
		}
	}
	return nil
}

func (b linuxBackend) Clear(ctx context.Context, plan Plan) error {
	if !b.authorized(plan) {
		return ErrPolicy
	}
	failed := false
	if len(plan.DNSServers) != 0 && command(ctx, resolvedCommand, "revert", b.link) != nil {
		failed = true
	}
	for _, route := range plan.Routes {
		if err := command(ctx, ipCommand, family(route), "route", "del", route.String(), "dev", b.link, "table", strconv.FormatUint(uint64(b.table), 10), "proto", routeProtocol); err != nil &&
			!b.routeAbsent(ctx, route) {
			failed = true
		}
	}
	for _, address := range plan.Addresses {
		host := netip.PrefixFrom(address.Addr(), address.Addr().BitLen())
		if err := command(ctx, ipCommand, family(address), "address", "flush", "dev", b.link, "to", host.String()); err != nil {
			failed = true
		}
	}
	if failed {
		return ErrCleanup
	}
	return nil
}

func (b linuxBackend) routeAbsent(ctx context.Context, route netip.Prefix) bool {
	cmd := exec.CommandContext(ctx, ipCommand, "-j", family(route), "route", "show", "table",
		strconv.FormatUint(uint64(b.table), 10), "exact", route.String(), "dev", b.link, "proto", routeProtocol)
	cmd.Env = append(cmd.Environ(), "LC_ALL=C")
	var out, stderr bytes.Buffer
	cmd.Stdout = &boundedOutput{out: &out}
	cmd.Stderr = &boundedOutput{out: &stderr}
	if err := cmd.Run(); err != nil {
		// iproute2 reports ENOENT on the dump of an unallocated table.
		var exit *exec.ExitError
		diagnostic := stderr.String()
		return ctx.Err() == nil && errors.As(err, &exit) && exit.ExitCode() == 2 &&
			(diagnostic == "Error: ipv4: FIB table does not exist.\nDump terminated\n" ||
				diagnostic == "Error: ipv6: FIB table does not exist.\nDump terminated\n" ||
				diagnostic == "RTNETLINK answers: No such file or directory\nDump terminated\n")
	}
	var entries []json.RawMessage
	return json.Unmarshal(out.Bytes(), &entries) == nil && len(entries) == 0
}

type boundedOutput struct{ out *bytes.Buffer }

func (w *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > 8192-w.out.Len() {
		return 0, errors.New("netlink response exceeds limit")
	}
	return w.out.Write(p)
}

func command(ctx context.Context, path string, args ...string) error {
	return exec.CommandContext(ctx, path, args...).Run()
}

func family(prefix netip.Prefix) string {
	if prefix.Addr().Is4() {
		return "-4"
	}
	return "-6"
}
