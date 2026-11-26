package client

import (
	"context"
	"errors"
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
// Certificate and PrivateKey must contain a matching PEM client key pair.
type TLSConfig struct {
	CA             []byte
	Certificate    []byte
	PrivateKey     []byte
	UseSystemRoots bool
}

// Credentials enables username/password authentication in addition to the
// required client certificate. Credentials travel inside verified TLS.
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
}

// ControlInfo reports negotiated settings for the active control session.
func (c *Client) ControlInfo() (ControlInfo, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.observeSession()
	link, ok := c.session.(*session.Session)
	if !ok || c.state != StateConnected {
		return ControlInfo{}, false
	}
	info, keyID := link.Info()
	return ControlInfo{
		TLSVersion: info.TLSVersion, DataCipher: info.Cipher, PeerID: info.PeerID,
		KeyID: keyID, TunnelIP: info.TunnelIP, TunnelIPv6: info.TunnelIPv6,
	}, true
}

func prepareHandshake(cfg Config) (handshakeFunc, error) {
	ciphers, err := crypt.DataCiphers(cfg.DataCiphers)
	if err != nil {
		return nil, configError("data ciphers")
	}
	digest := strings.ToUpper(cfg.Control.Digest)
	protection, err := control.NewProtection(control.Mode(cfg.Control.Mode),
		control.Direction(cfg.Control.Direction), digest, cfg.Control.Key)
	if err != nil {
		return nil, configError("control protection")
	}
	var user tlscontrol.Credentials
	if cfg.Credentials != nil {
		user = tlscontrol.Credentials(*cfg.Credentials)
		if err := user.Validate(); err != nil {
			return nil, configError("credentials")
		}
	}
	if cfg.TLS == nil {
		return nil, nil
	}
	settings, err := tlscontrol.ClientConfig(cfg.TLS.CA, cfg.TLS.Certificate, cfg.TLS.PrivateKey, cfg.TLS.UseSystemRoots)
	if err != nil {
		return nil, configError("TLS")
	}

	limit, rekey, deadline := cfg.MaxPacketSize, cfg.RekeyInterval, cfg.HandshakeTimeout
	return func(ctx context.Context, endpoint Endpoint, packets transport.PacketConn) (tunnel.PacketConn, error) {
		peer := settings.Clone()
		peer.ServerName = endpoint.ServerName
		opts := session.Options{
			TLS: tlscontrol.Options{
				TLS: peer, Network: endpoint.Network, Digest: digest, Ciphers: ciphers,
				Auth: tlscontrol.NewAuthentication(user),
			},
			Protection: protection, MaxPacketSize: limit, RekeyInterval: rekey, HandshakeLimit: deadline,
		}
		link, err := session.Open(ctx, packets, opts)
		if err != nil {
			return nil, setControlError(err)
		}
		return link, nil
	}, nil
}

func setControlError(err error) error {
	var code ErrorCode
	switch {
	case errors.Is(err, tlscontrol.ErrCertificate):
		code = CodeCertificate
	case errors.Is(err, tlscontrol.ErrAuth):
		code = CodeAuthentication
	case errors.Is(err, control.ErrTransport):
		code = CodeNetwork
	case errors.Is(err, control.ErrProtection):
		code = CodeConfig
	default:
		code = contextCode(err, CodeProtocol)
	}
	return &Error{Op: "handshake", Code: code}
}

// observeSession is called with c.mu held.
func (c *Client) observeSession() {
	s, ok := c.session.(*session.Session)
	if !ok {
		return
	}
	select {
	case <-s.Done():
		c.session = nil
		c.state = StateIdle
	default:
	}
}
