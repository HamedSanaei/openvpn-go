package client

import (
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/crypt"
	"github.com/hamedsanaei/openvpn-go/transport"
	"github.com/hamedsanaei/openvpn-go/tunnel"
)

// MaxEndpoints limits the number of configured remote candidates.
const MaxEndpoints = 64

// Endpoint identifies a remote and its expected server identity.
// Network defaults to udp and accepts tcp, udp4, udp6, tcp4 and tcp6.
// Port defaults to 1194. An empty ServerName uses the configured Host.
type Endpoint struct {
	Network    string
	Host       string
	Port       uint16
	ServerName string
	// VerifyX509Name is an optional exact certificate identity or an
	// additional common-name prefix check.
	VerifyX509Name X509Name
	// LocalAddress and LocalPort bind the built-in socket. Unset values
	// allow the OS to choose the source address and ephemeral port.
	LocalAddress netip.Addr
	LocalPort    uint16
	// ConnectTimeout, TunnelMTU and ExplicitExitNotify override or extend
	// client defaults for this remote. A zero timeout or MTU inherits.
	ConnectTimeout     time.Duration
	TunnelMTU          int
	ExplicitExitNotify bool
	// FixedAEAD explicitly selects the fixed AES-GCM compatibility policy
	// for this endpoint. An empty string requires modern negotiation.
	FixedAEAD string
}

// Validated returns an endpoint with defaults applied and its identity checked.
func (e Endpoint) Validated() (Endpoint, error) {
	if err := e.normalize(); err != nil {
		return Endpoint{}, err
	}
	return e, nil
}

func (e Endpoint) address() string {
	return net.JoinHostPort(e.Host, strconv.Itoa(int(e.Port)))
}

// Config configures a Client. New copies and validates the endpoint list.
// Endpoints retain their transport and identity settings through failover.
type Config struct {
	Endpoints []Endpoint
	Dialer    transport.Dialer
	Resolver  Resolver
	// ResolveRetry is the DNS retry budget within ConnectTimeout. Zero makes
	// one lookup. ResolveUntilDialDeadline uses the entire dial budget.
	ResolveRetry time.Duration
	// RemoteRandom shuffles all endpoint candidates once during New.
	RemoteRandom bool
	// Retry controls endpoint failover and reconnect during Run.
	Retry RetryPolicy
	// PushPolicy selects how authenticated tunnel metadata is handled.
	PushPolicy tunnel.PushPolicy

	// TLS supplies the trust anchors and client identity policy for Connect.
	TLS *TLSConfig
	// Credentials supplies username/password authentication when configured.
	Credentials *Credentials
	// Authentication delegates credential acquisition and optional interaction.
	Authentication Authentication
	// ExplicitExitNotify opts into bounded, authenticated shutdown on UDP.
	ExplicitExitNotify bool
	// TunnelMTU caps the inner IP packet size. Zero accepts the peer or frame limit.
	TunnelMTU int
	// Control selects outer control-channel protection.
	Control ControlProtection
	// EndpointControls optionally supplies one control setting per endpoint,
	// in the same order as Endpoints. Each entry replaces Control in full.
	EndpointControls []ControlProtection
	// AuthDigest sets the advertised OpenVPN auth digest and the default
	// tls-auth digest. A tls-auth Control.Digest takes precedence.
	AuthDigest string
	// DataCiphers restricts negotiation to the listed supported AEAD ciphers.
	// An empty list permits all built-in AEAD ciphers.
	DataCiphers []string

	// ConnectTimeout limits socket establishment. Zero uses 10 seconds.
	ConnectTimeout time.Duration
	// HandshakeTimeout limits control setup. Zero uses 60 seconds.
	HandshakeTimeout time.Duration
	// RekeyInterval sets the interval for client-initiated data rekey.
	// Zero uses one hour. The peer may also initiate a rekey.
	RekeyInterval time.Duration
	// DisableTimedRekey disables only timer-driven client rekeys. Peer
	// requests and data-channel key usage limits still require rekeying.
	DisableTimedRekey bool
	// MaxPacketSize caps a complete transport or tunnel packet. Zero uses
	// transport.DefaultPacketSize. A custom Dialer must enforce this limit
	// in its transport adapter.
	MaxPacketSize int
}

func (cfg Config) validated() (Config, error) {
	policy := cfg.PushPolicy
	if policy.Addresses > tunnel.PushReject || policy.Routes > tunnel.PushReject ||
		policy.DNS > tunnel.PushReject || policy.MTU > tunnel.PushReject {
		return Config{}, configError("push policy")
	}
	if len(cfg.Endpoints) == 0 || len(cfg.Endpoints) > MaxEndpoints {
		return Config{}, configError("endpoints")
	}
	if len(cfg.EndpointControls) != 0 && len(cfg.EndpointControls) != len(cfg.Endpoints) {
		return Config{}, configError("endpoint control settings")
	}
	cfg.Endpoints = slices.Clone(cfg.Endpoints)
	for i := range cfg.Endpoints {
		if err := cfg.Endpoints[i].normalize(); err != nil {
			return Config{}, err
		}
		if cfg.Dialer != nil && cfg.Endpoints[i].hasLocalBind() {
			return Config{}, configError("local bind with custom dialer")
		}
	}
	if cfg.ResolveRetry < ResolveUntilDialDeadline || cfg.ResolveRetry > 2*time.Minute {
		return Config{}, configError("resolution retry")
	}

	if cfg.ConnectTimeout < 0 || cfg.ConnectTimeout > 2*time.Minute {
		return Config{}, configError("connect timeout")
	}
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = 10 * time.Second
	}
	if cfg.HandshakeTimeout < 0 || cfg.HandshakeTimeout > 5*time.Minute {
		return Config{}, configError("handshake timeout")
	}
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = time.Minute
	}
	if !cfg.Retry.normalize(len(cfg.Endpoints)) {
		return Config{}, configError("retry policy")
	}
	if cfg.DisableTimedRekey && cfg.RekeyInterval != 0 {
		return Config{}, configError("rekey interval")
	}
	if cfg.RekeyInterval == 0 && !cfg.DisableTimedRekey {
		cfg.RekeyInterval = time.Hour
	} else if !cfg.DisableTimedRekey && (cfg.RekeyInterval < time.Second || cfg.RekeyInterval > 24*time.Hour) {
		return Config{}, configError("rekey interval")
	}
	if cfg.MaxPacketSize < 0 || cfg.MaxPacketSize > transport.MaxPacketSize {
		return Config{}, configError("packet size")
	}
	if cfg.MaxPacketSize == 0 {
		cfg.MaxPacketSize = transport.DefaultPacketSize
	}
	if !tunnel.ValidMTU(cfg.TunnelMTU) {
		return Config{}, configError("tunnel MTU")
	}
	if cfg.Dialer == nil {
		cfg.Dialer = transport.SocketDialer{MaxPacketSize: cfg.MaxPacketSize}
	}
	return cfg, nil
}

func (e *Endpoint) normalize() error {
	if err := e.VerifyX509Name.Validate(); err != nil {
		return err
	}
	if e.FixedAEAD != "" && e.FixedAEAD != crypt.AES128GCM && e.FixedAEAD != crypt.AES256GCM {
		return configError("fixed AEAD policy")
	}
	if e.Network == "" {
		e.Network = "udp"
	}
	if e.ConnectTimeout < 0 || e.ConnectTimeout > 2*time.Minute || !tunnel.ValidMTU(e.TunnelMTU) {
		return configError("endpoint timeout or MTU")
	}
	switch e.Network {
	case "udp", "udp4", "udp6", "tcp", "tcp4", "tcp6":
	default:
		return configError("endpoint network")
	}
	e.LocalAddress = e.LocalAddress.Unmap()
	if e.LocalAddress.IsValid() && (e.LocalAddress.IsMulticast() ||
		strings.HasSuffix(e.Network, "4") && !e.LocalAddress.Is4() ||
		strings.HasSuffix(e.Network, "6") && !e.LocalAddress.Is6()) {
		return configError("local bind address")
	}
	if e.Port == 0 {
		e.Port = 1194
	}

	if addr, err := netip.ParseAddr(e.Host); err == nil {
		switch {
		case e.addressFamily() == "ip4" && !addr.Unmap().Is4():
			return configError("endpoint address family")
		case e.addressFamily() == "ip6" && addr.Unmap().Is4():
			return configError("endpoint address family")
		}
		if e.ServerName == "" {
			e.ServerName = addr.WithZone("").Unmap().String()
		}
	} else if !validHostname(e.Host) {
		return configError("endpoint host")
	}

	if e.ServerName == "" {
		e.ServerName = strings.TrimSuffix(e.Host, ".")
	}
	if addr, err := netip.ParseAddr(e.ServerName); err == nil {
		if addr.Zone() != "" {
			return configError("server name")
		}
	} else if !validHostname(e.ServerName) {
		return configError("server name")
	}
	return nil
}

func validHostname(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for label := range strings.SplitSeq(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}
