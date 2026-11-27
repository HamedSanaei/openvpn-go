package profile

import (
	"net/netip"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/control"
	"github.com/hamedsanaei/openvpn-go/internal/crypt"
	"github.com/hamedsanaei/openvpn-go/tunnel"
)

type remote struct {
	loc      location
	endpoint client.Endpoint
}

type connection struct {
	network        string
	port           uint16
	remote         remote
	localAddress   netip.Addr
	localPort      uint16
	portLocal      uint16
	bindMode       string
	localBindSet   bool
	localSourceSet bool
	pollTimeout    time.Duration
	mtu            int
	exit           bool
	exitSet        bool
	fixedAEAD      string
	fixedDataV1    bool
	fixedLoc       location

	protection      *material
	direction       client.KeyDirection
	directionLoc    location
	localProtection bool
	localDirection  bool
}

func (p *parser) openConnection(loc location) error {
	switch {
	case p.block != nil:
		return loc.diagnostic(CodeScope)
	case len(p.remotes) != 0:
		return loc.diagnostic(CodeConflict)
	case len(p.blocks) == client.MaxEndpoints:
		return loc.diagnostic(CodeLimit)
	}
	block := p.defaults
	block.localProtection, block.localDirection = false, false
	block.localBindSet, block.localSourceSet = false, false
	p.block, p.blockLoc = &block, loc
	return nil
}

func (p *parser) closeConnection(line int) error {
	if p.block == nil {
		return (location{line: line, name: "connection"}).diagnostic(CodeSyntax)
	}
	block := p.block
	p.block = nil
	if block.remote.loc.line == 0 {
		return (location{line: p.blockLoc.line, name: "remote"}).diagnostic(CodeRequired)
	}
	p.blocks = append(p.blocks, *block)
	return nil
}

func (p *parser) connection() *connection {
	if p.block != nil {
		return p.block
	}
	return &p.defaults
}

func (p *parser) applyConnection(loc location, args []string) error {
	c := p.connection()
	switch loc.name {
	case "proto":
		net := network(args[0])
		if net == "" {
			return loc.diagnostic(CodeUnsupported)
		}
		c.network = net
	case "port", "rport":
		n, ok := uintValue(args[0], 16)
		if !ok || n == 0 {
			return loc.diagnostic(CodeValue)
		}
		c.port = uint16(n)
		if loc.name == "port" {
			c.portLocal = uint16(n)
		}
	case "bind", "nobind":
		if c.localBindSet && c.bindMode != loc.name ||
			loc.name == "nobind" && c.localSourceSet {
			return loc.diagnostic(CodeConflict)
		}
		c.bindMode, c.localBindSet = loc.name, true
		if c.bindMode == "nobind" {
			c.localAddress, c.localPort = netip.Addr{}, 0
		}
	case "local":
		ip, err := netip.ParseAddr(args[0])
		if err != nil || ip.IsMulticast() {
			return loc.diagnostic(CodeValue)
		}
		if c.localBindSet && c.bindMode == "nobind" {
			return loc.diagnostic(CodeConflict)
		}
		c.localAddress = ip.Unmap()
		c.localSourceSet = true
	case "lport":
		n, ok := uintValue(args[0], 16)
		if !ok || n == 0 {
			return loc.diagnostic(CodeValue)
		}
		if c.localBindSet && c.bindMode == "nobind" {
			return loc.diagnostic(CodeConflict)
		}
		c.localPort = uint16(n)
		c.localSourceSet = true
	case "connect-timeout", "server-poll-timeout":
		timeout, ok := seconds(args[0], 1, 300)
		if !ok {
			return loc.diagnostic(CodeValue)
		}
		c.pollTimeout = timeout
	case "tun-mtu":
		n, ok := uintValue(args[0], 16)
		if !ok || n == 0 || !tunnel.ValidMTU(int(n)) {
			return loc.diagnostic(CodeValue)
		}
		c.mtu = int(n)
	case "explicit-exit-notify":
		exit := true
		if len(args) != 0 {
			n, ok := uintValue(args[0], 8)
			if !ok {
				return loc.diagnostic(CodeValue)
			}
			exit = n != 0
		}
		c.exit, c.exitSet = exit, true
	case "compat-fixed-aead", "compat-fixed-aead-v1":
		if c.fixedAEAD != "" {
			return loc.diagnostic(CodeConflict)
		}
		if args[0] != crypt.AES128GCM && args[0] != crypt.AES256GCM {
			return loc.diagnostic(CodeUnsupported)
		}
		c.fixedAEAD, c.fixedLoc, c.fixedDataV1 = args[0], loc, loc.name == "compat-fixed-aead-v1"
	case "key-direction":
		direction, ok := keyDirection(args[0])
		if !ok {
			return loc.diagnostic(CodeValue)
		}
		if c.localDirection && c.direction != direction {
			return loc.diagnostic(CodeConflict)
		}
		c.direction, c.directionLoc, c.localDirection = direction, loc, true
	case "remote":
		return p.addRemote(loc, args, c)
	}
	return nil
}

func (p *parser) addRemote(loc location, args []string, c *connection) error {
	e := client.Endpoint{Host: args[0]}
	if len(args) >= 2 {
		port, ok := uintValue(args[1], 16)
		if !ok || port == 0 {
			return loc.diagnostic(CodeValue)
		}
		e.Port = uint16(port)
	}
	if len(args) == 3 {
		e.Network = network(args[2])
		if e.Network == "" {
			return loc.diagnostic(CodeUnsupported)
		}
	}
	r := remote{loc: loc, endpoint: e}
	if p.block == nil {
		switch {
		case len(p.blocks) != 0:
			return loc.diagnostic(CodeConflict)
		case len(p.remotes) == client.MaxEndpoints:
			return loc.diagnostic(CodeLimit)
		}
		p.remotes = append(p.remotes, r)
		return nil
	}
	if c.remote.loc.line != 0 {
		return loc.diagnostic(CodeConflict)
	}
	c.remote = r
	if e.Port != 0 {
		c.port = e.Port
	}
	if e.Network != "" {
		c.network = e.Network
	}
	return nil
}

func (p *parser) endpoints() error {
	if p.defaults.fixedAEAD != "" && (len(p.remotes) != 1 || len(p.blocks) != 0) {
		return p.defaults.fixedLoc.diagnostic(CodeScope)
	}
	if len(p.remotes) != 0 {
		for _, r := range p.remotes {
			e := r.endpoint
			if e.Port == 0 {
				e.Port = p.defaults.port
			}
			if e.Network == "" {
				e.Network = p.defaults.network
			}
			if err := p.appendEndpoint(e, r.loc, p.defaults); err != nil {
				return err
			}
		}
		protection, err := p.loadProtection(p.defaults)
		p.cfg.Control = protection
		return err
	}

	for _, c := range p.blocks {
		e := c.remote.endpoint
		e.Port, e.Network = c.port, c.network
		if err := p.appendEndpoint(e, c.remote.loc, c); err != nil {
			return err
		}
		protection, err := p.loadProtection(c)
		if err != nil {
			return err
		}
		p.cfg.EndpointControls = append(p.cfg.EndpointControls, protection)
	}
	return nil
}

func (p *parser) appendEndpoint(e client.Endpoint, loc location, c connection) error {
	if c.fixedAEAD != "" && (c.protection != nil ||
		p.usesPasswordOnly() && !c.fixedDataV1 ||
		len(p.cfg.DataCiphers) != 0 && (len(p.cfg.DataCiphers) != 1 || p.cfg.DataCiphers[0] != c.fixedAEAD)) {
		return c.fixedLoc.diagnostic(CodeConflict)
	}
	if c.fixedDataV1 && (!p.cfg.TLS.RequireServerUsage || p.identity.Mode != client.X509CommonName ||
		p.ca == nil || p.auth == nil || p.cfg.Authentication.Interactive()) {
		return c.fixedLoc.diagnostic(CodeConflict)
	}
	e.FixedAEAD, e.FixedAEADDataV1 = c.fixedAEAD, c.fixedDataV1
	if p.opts.ProtonVPNVerifyIP {
		ip, err := netip.ParseAddr(e.Host)
		if err != nil || ip.Zone() != "" || ip.Is4In6() {
			return loc.diagnostic(CodeValue)
		}
	}
	e.VerifyX509Name = p.identity
	if p.opts.ExpressVPNManual {
		e.ExpressVPNFragmentSize = p.express.fragment
		if c.protection == nil || c.protection.loc.name != "tls-auth" {
			return (location{name: "tls-auth"}).diagnostic(CodeRequired)
		}
	}
	e.LocalAddress, e.LocalPort = c.localAddress, c.localPort
	e.TunnelMTU = c.mtu
	e.ExplicitExitNotify = c.exit || p.opts.ExpressVPNManual && !c.exitSet
	e.ServerPollTimeout = c.pollTimeout
	if c.bindMode == "bind" && e.LocalPort == 0 {
		e.LocalPort = c.portLocal
		if e.LocalPort == 0 {
			e.LocalPort = 1194
		}
	}
	checked, err := e.Validated()
	if err != nil {
		return loc.diagnostic(CodeValue)
	}
	p.cfg.Endpoints = append(p.cfg.Endpoints, checked)
	return nil
}

func (p *parser) setProtection(m *material) error {
	c := p.connection()
	if c.localProtection {
		return m.loc.diagnostic(CodeConflict)
	}
	if p.block != nil && !c.localDirection && c.protection != nil &&
		c.protection.loc.name == "tls-auth" && m.loc.name != "tls-auth" {
		c.direction, c.directionLoc = client.KeyBidirectional, location{}
	}
	c.protection, c.localProtection = m, true
	return nil
}

func (p *parser) loadProtection(c connection) (client.ControlProtection, error) {
	var result client.ControlProtection
	m := c.protection
	if c.direction != client.KeyBidirectional && (m == nil || m.loc.name != "tls-auth") {
		return result, c.directionLoc.diagnostic(CodeConflict)
	}
	if m == nil {
		return result, nil
	}
	switch m.loc.name {
	case "tls-auth":
		result.Mode = client.ControlTLSAuth
		result.Digest = p.cfg.AuthDigest
		result.Direction = c.direction
		if m.direction != client.KeyBidirectional {
			if c.direction != client.KeyBidirectional && c.direction != m.direction {
				return result, m.loc.diagnostic(CodeConflict)
			}
			result.Direction = m.direction
		}
	case "tls-crypt":
		result.Mode = client.ControlTLSCrypt
	case "tls-crypt-v2":
		result.Mode = client.ControlTLSCryptV2
	}
	var err error
	result.Key, err = p.load(m)
	if err != nil {
		return result, err
	}
	if _, err := control.NewProtection(control.Mode(result.Mode), control.Direction(result.Direction),
		result.Digest, result.Key); err != nil {
		return result, m.loc.diagnostic(CodeMaterial)
	}
	return result, nil
}

func network(s string) string {
	switch s {
	case "udp", "udp4", "udp6", "tcp", "tcp4", "tcp6":
		return s
	case "tcp-client":
		return "tcp"
	case "tcp4-client":
		return "tcp4"
	case "tcp6-client":
		return "tcp6"
	default:
		return ""
	}
}

func keyDirection(s string) (client.KeyDirection, bool) {
	switch s {
	case "0":
		return client.KeyDirection0, true
	case "1":
		return client.KeyDirection1, true
	default:
		return client.KeyBidirectional, false
	}
}
