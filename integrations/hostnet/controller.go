// Package hostnet applies authenticated tunnel settings in an owned host scope.
package hostnet

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/tunnel"
)

var (
	ErrPolicy  = errors.New("host network settings exceed lease policy")
	ErrPending = errors.New("host network lease requires cleanup")
	ErrJournal = errors.New("host network journal unavailable")
	ErrApply   = errors.New("host network setup failed")
	ErrCleanup = errors.New("host network cleanup failed")
)

// Policy is trusted host configuration, independent of the remote profile.
// It assigns one dedicated link and routing table to one controller.
type Policy struct {
	Link                     string
	Table                    uint32
	AddressAllow, RouteAllow []netip.Prefix
	DNSServers               []netip.Addr
	DNSDomains               []string
}

// Plan contains only normalized, authorized arguments. Backends must own
// the link's provisioned namespace, the route table and its DNS scope.
type Plan struct {
	Link       string
	Table      uint32
	Addresses  []netip.Prefix
	Routes     []netip.Prefix
	DNSServers []netip.Addr
	DNSDomains []string
}

// Backend applies a plan and clears all of its resources, even if only
// part of Apply succeeded. Clear must be idempotent.
type Backend interface {
	Apply(context.Context, Plan) error
	Clear(context.Context, Plan) error
}

// Journal records a plan durably before its first side effect. A nil plan
// from Load means there is no visible lease. Delete must idempotently
// confirm durable absence, including after a failed prior deletion.
type Journal interface {
	Load() (*Plan, error)
	Save(Plan) error
	Delete() error
}

type Controller struct {
	mu         sync.Mutex
	policy     Policy
	backend    Backend
	journal    Journal
	active     *Plan
	cleanup    error
	intentOnly bool
}

func New(policy Policy, backend Backend, journal Journal) (*Controller, error) {
	if backend == nil || journal == nil || !validScope(policy.Link, policy.Table) ||
		len(policy.AddressAllow) > 64 || len(policy.RouteAllow) > 64 ||
		len(policy.DNSServers) > 8 || len(policy.DNSDomains) > 16 {
		return nil, ErrPolicy
	}
	if validator, ok := backend.(interface{ acceptsPolicy(Policy) bool }); ok && !validator.acceptsPolicy(policy) {
		return nil, ErrPolicy
	}
	for _, prefixes := range [][]netip.Prefix{policy.AddressAllow, policy.RouteAllow} {
		for _, prefix := range prefixes {
			if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() {
				return nil, ErrPolicy
			}
		}
	}
	for _, server := range policy.DNSServers {
		if !validServer(server) {
			return nil, ErrPolicy
		}
	}
	for _, domain := range policy.DNSDomains {
		if !validDomain(domain) {
			return nil, ErrPolicy
		}
	}
	policy.AddressAllow = slices.Clone(policy.AddressAllow)
	policy.RouteAllow = slices.Clone(policy.RouteAllow)
	policy.DNSServers = slices.Clone(policy.DNSServers)
	policy.DNSDomains = slices.Clone(policy.DNSDomains)
	return &Controller{policy: policy, backend: backend, journal: journal}, nil
}

// Configure implements client.TunnelConfigurer. Recovery must precede a
// new generation when the journal contains a previous lease.
func (c *Controller) Configure(ctx context.Context, gen client.TunnelGeneration) (func(), error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active != nil || c.cleanup != nil {
		return nil, ErrPending
	}
	previous, err := c.journal.Load()
	if err != nil {
		return nil, ErrJournal
	}
	if previous != nil {
		return nil, ErrPending
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	plan, err := c.policy.plan(gen.Control.Tunnel)
	if err != nil {
		return nil, err
	}
	if err := c.journal.Save(plan); err != nil {
		c.cleanup, c.intentOnly = ErrJournal, true
		return nil, ErrJournal
	}
	c.active = &plan
	applyCtx, stop := context.WithTimeout(ctx, 5*time.Second)
	err = c.backend.Apply(applyCtx, plan)
	timedOut := applyCtx.Err()
	stop()
	if err != nil || timedOut != nil {
		c.rollback()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.Join(ErrApply, c.cleanup)
	}
	return func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.active == &plan {
			c.rollback()
		}
	}, nil
}

func (c *Controller) rollback() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c.cleanup = c.clear(ctx, *c.active)
	c.active = nil
}

// Recover removes any previous lease described by the journal. Recovery
// validates the saved plan against this controller's current host policy.
// In-process journal failures remain pending until deletion is durably
// confirmed. On restart, a retained authorized intent is recovered as
// possibly applied and an absent record follows the journal's durability contract.
func (c *Controller) Recover(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active != nil {
		return ErrPending
	}
	plan, err := c.journal.Load()
	if err != nil {
		return ErrJournal
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if plan == nil && c.cleanup == nil {
		return nil
	}
	if plan != nil && !c.policy.authorizes(*plan) {
		return ErrPolicy
	}
	if plan == nil && errors.Is(c.cleanup, ErrCleanup) {
		return c.cleanup
	}
	if plan == nil || c.intentOnly {
		c.cleanup = c.deleteIntent()
	} else {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		c.cleanup = c.clear(ctx, *plan)
	}
	if c.cleanup == nil {
		c.intentOnly = false
	}
	return c.cleanup
}

// CleanupError reports a rollback failure that requires Recover.
func (c *Controller) CleanupError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cleanup
}

func (c *Controller) clear(ctx context.Context, plan Plan) error {
	if err := c.backend.Clear(ctx, plan); err != nil {
		return ErrCleanup
	}
	return c.deleteIntent()
}

func (c *Controller) deleteIntent() error {
	if err := c.journal.Delete(); err != nil {
		return ErrJournal
	}
	return nil
}

func (p Policy) plan(cfg tunnel.Configuration) (Plan, error) {
	plan := Plan{Link: p.Link, Table: p.Table}
	for _, addr := range []netip.Prefix{cfg.IPv4, cfg.IPv6} {
		if addr.IsValid() {
			plan.Addresses = append(plan.Addresses, addr)
		}
	}
	for _, route := range cfg.Routes() {
		if route.Gateway.IsValid() || route.HasMetric {
			return Plan{}, ErrPolicy
		}
		plan.Routes = append(plan.Routes, route.Destination)
	}
	dns := cfg.DNS()
	if dns.Domain != "" || len(dns.SearchDomains) != 0 || len(dns.Servers) > 1 {
		return Plan{}, ErrPolicy
	}
	for _, group := range dns.Servers {
		if group.Transport != "" && group.Transport != tunnel.DNSPlain ||
			group.DNSSEC != "" || group.ServerName != "" || len(group.ResolveDomains) == 0 {
			return Plan{}, ErrPolicy
		}
		for _, server := range group.Addresses {
			if server.Port() != 53 {
				return Plan{}, ErrPolicy
			}
			plan.DNSServers = append(plan.DNSServers, server.Addr())
		}
		plan.DNSDomains = slices.Clone(group.ResolveDomains)
	}
	if !p.authorizes(plan) {
		return Plan{}, ErrPolicy
	}
	return plan, nil
}

func (p Policy) authorizes(plan Plan) bool {
	if plan.Link != p.Link || plan.Table != p.Table || len(plan.Addresses) == 0 ||
		len(plan.Addresses) > 2 || len(plan.Routes) > 64 ||
		len(plan.DNSServers) > 8 || len(plan.DNSDomains) > 16 ||
		(len(plan.DNSServers) == 0) != (len(plan.DNSDomains) == 0) {
		return false
	}
	for _, address := range plan.Addresses {
		if !address.IsValid() || !validServer(address.Addr()) || !allowedPrefix(p.AddressAllow, address) {
			return false
		}
	}
	for _, route := range plan.Routes {
		if !route.IsValid() || route != route.Masked() || !allowedPrefix(p.RouteAllow, route) {
			return false
		}
	}
	for _, address := range plan.DNSServers {
		if !slices.Contains(p.DNSServers, address) {
			return false
		}
	}
	for _, domain := range plan.DNSDomains {
		if !slices.Contains(p.DNSDomains, domain) {
			return false
		}
	}
	return true
}

func allowedPrefix(allowed []netip.Prefix, value netip.Prefix) bool {
	return slices.ContainsFunc(allowed, func(a netip.Prefix) bool {
		return a.Bits() <= value.Bits() && a.Contains(value.Addr())
	})
}

func validScope(link string, table uint32) bool {
	if len(link) == 0 || len(link) > 15 || link[0] < 'a' || link[0] > 'z' ||
		table < 1000 || table > 2147483647 {
		return false
	}
	for _, ch := range link {
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-') {
			return false
		}
	}
	return true
}

func validServer(addr netip.Addr) bool {
	return addr.IsGlobalUnicast() && !addr.Is4In6() && addr.Zone() == ""
}

func validDomain(domain string) bool {
	if len(domain) > 253 {
		return false
	}
	for label := range strings.SplitSeq(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}
