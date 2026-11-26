package client

import (
	"context"
	"crypto/tls"
	"net/netip"
	"strings"

	"github.com/hamedsanaei/openvpn-go/internal/control"
	"github.com/hamedsanaei/openvpn-go/internal/crypt"
	"github.com/hamedsanaei/openvpn-go/internal/session"
	"github.com/hamedsanaei/openvpn-go/internal/tlscontrol"
	"github.com/hamedsanaei/openvpn-go/transport"
	"github.com/hamedsanaei/openvpn-go/tunnel"
)

// TLSConfig supplies the verified control channel's trust and client identity.
// CA can contain a PEM CA bundle. System roots are added only when requested.
// Certificate and PrivateKey contain a matching PEM client key pair.
type TLSConfig struct {
	CA             []byte
	Certificate    []byte
	PrivateKey     []byte
	UseSystemRoots bool
	// AllowPasswordOnly allows omission of both identity fields when valid
	// Credentials are configured. Server verification remains mandatory.
	AllowPasswordOnly bool
	// MinVersion and MaxVersion use crypto/tls version constants.
	// Zero selects TLS 1.2 for the minimum and TLS 1.3 for the maximum.
	MinVersion, MaxVersion uint16
	// RequireServerUsage requires explicit leaf KU and server-auth EKU.
	RequireServerUsage bool
}

// Credentials enables username/password authentication inside verified TLS.
type Credentials struct {
	Username string
	Password string
}

// ControlMode selects the optional outer protection of the TLS control channel.
type ControlMode uint8

const (
	ControlPlain      ControlMode = ControlMode(control.Plain)
	ControlTLSAuth    ControlMode = ControlMode(control.TLSAuth)
	ControlTLSCrypt   ControlMode = ControlMode(control.TLSCrypt)
	ControlTLSCryptV2 ControlMode = ControlMode(control.TLSCryptV2)
)

// KeyDirection selects the directional key slots for tls-auth.
type KeyDirection uint8

const (
	KeyBidirectional KeyDirection = KeyDirection(control.Bidirectional)
	KeyDirection0    KeyDirection = KeyDirection(control.Direction0)
	KeyDirection1    KeyDirection = KeyDirection(control.Direction1)
)

// ControlProtection contains a Static Key V1 or tls-crypt-v2 client PEM.
// Digest and Direction are optional tls-auth settings. Its default digest
// is SHA1, and omitting direction uses the same slot in each direction.
type ControlProtection struct {
	Mode      ControlMode
	Key       []byte
	Digest    string
	Direction KeyDirection
}

// ControlInfo describes the authenticated control negotiation.
type ControlInfo struct {
	TLSVersion uint16
	DataCipher string
	PeerID     uint32
	KeyID      uint8
	TunnelIP   netip.Addr
	TunnelIPv6 netip.Prefix
	Tunnel     tunnel.Configuration
}

// ControlInfo reports negotiated settings for the active control session.
func (c *Client) ControlInfo() (ControlInfo, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	active := c.liveConnection()
	if active == nil {
		return ControlInfo{}, false
	}
	return controlInfo(active)
}

func controlInfo(active *connection) (ControlInfo, bool) {
	link, ok := active.link.(interface {
		Info() (tlscontrol.Negotiation, uint8)
	})
	if !ok {
		return ControlInfo{}, false
	}
	info, keyID := link.Info()
	return ControlInfo{
		TLSVersion: info.TLSVersion, DataCipher: info.Cipher, PeerID: info.PeerID,
		KeyID: keyID, TunnelIP: info.Tunnel.IPv4.Addr(), TunnelIPv6: info.Tunnel.IPv6, Tunnel: info.Tunnel,
	}, true
}

func prepareHandshakes(cfg Config) ([]handshakeFunc, error) {
	ciphers, err := crypt.DataCiphers(cfg.DataCiphers)
	if err != nil {
		return nil, configError("data ciphers")
	}
	authDigest := strings.ToUpper(cfg.AuthDigest)
	if !control.ValidAuthDigest(authDigest) {
		return nil, configError("auth digest")
	}
	var user tlscontrol.Credentials
	if cfg.Credentials != nil {
		user = tlscontrol.Credentials(*cfg.Credentials)
		if err := user.Validate(); err != nil {
			return nil, configError("credentials")
		}
	}
	var settings *tls.Config
	if cfg.TLS != nil {
		optional := cfg.TLS.AllowPasswordOnly && cfg.Credentials != nil
		settings, err = tlscontrol.ClientConfig(cfg.TLS.CA, cfg.TLS.Certificate, cfg.TLS.PrivateKey, cfg.TLS.UseSystemRoots, optional)
		if err != nil || !tlscontrol.ValidVersions(cfg.TLS.MinVersion, cfg.TLS.MaxVersion) {
			return nil, configError("TLS")
		}
		if cfg.TLS.MinVersion != 0 {
			settings.MinVersion = cfg.TLS.MinVersion
		}
		if cfg.TLS.MaxVersion != 0 {
			settings.MaxVersion = cfg.TLS.MaxVersion
		}
	}

	// Validate the common setting even when no TLS session is configured.
	common, digest, err := cfg.Control.prepare(authDigest)
	if err != nil {
		return nil, err
	}
	handshakes := make([]handshakeFunc, len(cfg.Endpoints))
	limits := session.Options{
		MaxPacketSize: cfg.MaxPacketSize, RekeyInterval: cfg.RekeyInterval, HandshakeLimit: cfg.HandshakeTimeout,
	}
	for i, endpoint := range cfg.Endpoints {
		protection, wireDigest := common, digest
		if len(cfg.EndpointControls) != 0 {
			protection, wireDigest, err = cfg.EndpointControls[i].prepare(authDigest)
			if err != nil {
				return nil, err
			}
		}
		if settings == nil {
			continue
		}
		peer := tlscontrol.PeerConfig(settings, endpoint.ServerName, string(endpoint.VerifyX509Name.Mode),
			endpoint.VerifyX509Name.Value, cfg.TLS.RequireServerUsage)
		opts := limits
		opts.TLS = tlscontrol.Options{TLS: peer, Digest: wireDigest, Ciphers: ciphers, PushPolicy: cfg.PushPolicy}
		opts.Protection = protection
		handshakes[i] = openHandshake(opts, user)
	}
	return handshakes, nil
}

func (p ControlProtection) prepare(authDigest string) (control.Protection, string, error) {
	digest := strings.ToUpper(p.Digest)
	if p.Mode == ControlTLSAuth && digest == "" {
		digest = authDigest
	}
	protection, err := control.NewProtection(control.Mode(p.Mode), control.Direction(p.Direction), digest, p.Key)
	if err != nil {
		return control.Protection{}, "", configError("control protection")
	}
	if digest == "" {
		digest = authDigest
	}
	return protection, digest, nil
}

func openHandshake(config session.Options, user tlscontrol.Credentials) handshakeFunc {
	return func(ctx context.Context, endpoint Endpoint, packets transport.PacketConn) (tunnel.PacketConn, error) {
		opts := config
		opts.TLS.Network = endpoint.Network
		opts.TLS.Auth = tlscontrol.NewAuthentication(user)
		link, err := session.Open(ctx, packets, opts)
		if err != nil {
			return nil, setControlError(err)
		}
		return link, nil
	}
}

func setControlError(err error) error {
	return &Error{Op: "handshake", Code: packetErrorCode(err, CodeProtocol)}
}
