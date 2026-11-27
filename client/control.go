package client

import (
	"context"
	"crypto"
	"crypto/fips140"
	"crypto/tls"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/control"
	"github.com/hamedsanaei/openvpn-go/internal/crypt"
	"github.com/hamedsanaei/openvpn-go/internal/data"
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
	// ServerFingerprints adds an allow-list of colon-separated SHA-256
	// leaf fingerprints to the configured CA and endpoint identity checks.
	ServerFingerprints []string
	// CRL is a PEM bundle of complete, current certificate revocation lists
	// covering every non-root certificate in the accepted server chain.
	CRL []byte
	// Signer or KeyProvider can supply the matching key for Certificate.
	// They are mutually exclusive with each other and PrivateKey.
	Signer      crypto.Signer
	KeyProvider func(context.Context) (crypto.Signer, error)
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

// Challenge is a text prompt from a verified OpenVPN peer. Prompt is
// untrusted display text and may contain sensitive information.
type Challenge = tlscontrol.Challenge

// Authentication callbacks run only after peer verification. They must honor
// context cancellation and must not call Client.Close from the callback.
// Credentials reacquires secrets when no session token is available. WebAuth
// hands the HTTPS URL to the application and awaits completion of its local
// interaction. The verified VPN peer still decides whether login succeeded.
type Authentication struct {
	Credentials func(context.Context) (Credentials, error)
	Challenge   func(context.Context, Challenge) (string, error)
	WebAuth     func(context.Context, string) error
	// AllowPassivePending accepts a deferred server decision without a local callback.
	AllowPassivePending bool
	// PendingTimeout permits verified AUTH_PENDING to extend setup by at
	// most this duration, up to five minutes and the caller's deadline.
	// Zero keeps the existing handshake deadline.
	PendingTimeout time.Duration
}

// Interactive reports whether the configuration permits a pending server
// decision or an interactive authentication exchange.
func (a Authentication) Interactive() bool {
	return a.Challenge != nil || a.WebAuth != nil || a.AllowPassivePending
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

type KeyDerivation = crypt.Derivation

const (
	KeyDerivationTLSExporter = crypt.TLSExporter
	KeyDerivationClassicKM2  = crypt.ClassicKM2
	DataFormatV2             = "data_v2"
	DataFormatV1             = "data_v1"
)

// ControlInfo describes the authenticated control negotiation.
type ControlInfo struct {
	TLSVersion    uint16
	DataCipher    string
	KeyDerivation KeyDerivation
	DataFormat    string
	PeerID        uint32
	KeyID         uint8
	TunnelIP      netip.Addr
	TunnelIPv6    netip.Prefix
	Tunnel        tunnel.Configuration
	// MaxTunnelPacketSize is the active ceiling for a complete inner IP packet.
	MaxTunnelPacketSize int
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
	format := DataFormatV2
	if info.DataV1 {
		format = DataFormatV1
	}
	return ControlInfo{
		TLSVersion: info.TLSVersion, DataCipher: info.Cipher, PeerID: info.PeerID,
		KeyDerivation: info.Derivation, DataFormat: format,
		KeyID: keyID, TunnelIP: info.Tunnel.IPv4.Addr(), TunnelIPv6: info.Tunnel.IPv6, Tunnel: info.Tunnel,
		MaxTunnelPacketSize: info.PacketMTU,
	}, true
}

func prepareHandshakes(cfg Config) ([]handshakeFunc, error) {
	ciphers, err := crypt.DataCiphers(cfg.DataCiphers)
	if err == nil && cfg.TLS != nil {
		ciphers, err = crypt.RuntimeDataCiphers(ciphers, len(cfg.DataCiphers) != 0)
	}
	if err != nil {
		return nil, configError("data ciphers")
	}
	authDigest := strings.ToUpper(cfg.AuthDigest)
	if !control.ValidAuthDigest(authDigest) {
		return nil, configError("auth digest")
	}
	var user tlscontrol.Credentials
	auth := tlscontrol.Interaction{Challenge: cfg.Authentication.Challenge, WebAuth: cfg.Authentication.WebAuth,
		AllowPassivePending: cfg.Authentication.AllowPassivePending, PendingTimeout: cfg.Authentication.PendingTimeout}
	if auth.PendingTimeout < 0 || auth.PendingTimeout > tlscontrol.MaxPendingTimeout {
		return nil, configError("pending authentication timeout")
	}
	if provider := cfg.Authentication.Credentials; provider != nil {
		if cfg.Credentials != nil {
			return nil, configError("credentials")
		}
		auth.Credentials = func(ctx context.Context) (tlscontrol.Credentials, error) {
			user, err := provider(ctx)
			return tlscontrol.Credentials(user), err
		}
	}
	if cfg.Credentials != nil {
		user = tlscontrol.Credentials(*cfg.Credentials)
		if err := user.Validate(); err != nil {
			return nil, configError("credentials")
		}
	}
	var settings *tls.Config
	var trust tlscontrol.ServerTrust
	if cfg.TLS != nil {
		optional := cfg.TLS.AllowPasswordOnly && (cfg.Credentials != nil || auth.Credentials != nil)
		tlsSettings := cfg.TLS
		certificate, key := tlsSettings.Certificate, tlsSettings.PrivateKey
		external := tlsSettings.Signer != nil || tlsSettings.KeyProvider != nil
		if external && len(key) != 0 {
			return nil, configError("TLS identity")
		}
		if external {
			certificate = nil
		}
		if len(tlsSettings.CA)+len(tlsSettings.Certificate)+len(key)+len(tlsSettings.CRL) > 1<<20 {
			return nil, configError("TLS material")
		}
		settings, err = tlscontrol.ClientConfig(tlsSettings.CA, certificate, key, tlsSettings.UseSystemRoots, optional || external)
		if err != nil || !tlscontrol.ValidVersions(cfg.TLS.MinVersion, cfg.TLS.MaxVersion) {
			return nil, configError("TLS")
		}
		if external && tlscontrol.SetKeyProvider(settings, tlsSettings.Certificate,
			tlsSettings.Signer, tlsSettings.KeyProvider) != nil {
			return nil, configError("TLS identity")
		}
		trust, err = tlscontrol.ParseServerTrust(tlsSettings.ServerFingerprints, tlsSettings.CRL)
		if err != nil {
			return nil, configError("TLS server trust")
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
		TunnelMTU: cfg.TunnelMTU, ReceiveQueueSize: cfg.ReceiveQueueSize,
	}
	for i, endpoint := range cfg.Endpoints {
		protection, wireDigest := common, digest
		mode := cfg.Control.Mode
		if len(cfg.EndpointControls) != 0 {
			mode = cfg.EndpointControls[i].Mode
			protection, wireDigest, err = cfg.EndpointControls[i].prepare(authDigest)
			if err != nil {
				return nil, err
			}
		}
		if endpoint.VerifyX509Name.Mode == X509CommonNamePrefix &&
			(settings == nil || len(cfg.TLS.CA) == 0 || cfg.TLS.UseSystemRoots || !cfg.TLS.RequireServerUsage) {
			return nil, configError("X.509 prefix policy")
		}
		if endpoint.ExpressVPNFragmentSize != 0 &&
			(settings == nil || mode != ControlTLSAuth || endpoint.FixedAEAD != "" ||
				endpoint.VerifyX509Name.Mode != X509CommonNamePrefix || cfg.TLS.AllowPasswordOnly ||
				cfg.Credentials == nil && auth.Credentials == nil) {
			return nil, configError("ExpressVPN data framing policy")
		}
		offer := ciphers
		if fixed := endpoint.FixedAEAD; fixed != "" {
			if settings == nil || (!endpoint.FixedAEADDataV1 && len(cfg.TLS.Certificate) == 0) || mode != ControlPlain || fips140.Enabled() ||
				len(cfg.DataCiphers) != 0 && (len(ciphers) != 1 || ciphers[0] != fixed) {
				return nil, configError("fixed AEAD policy")
			}
			if endpoint.FixedAEADDataV1 && (len(cfg.TLS.CA) == 0 || cfg.TLS.UseSystemRoots ||
				!cfg.TLS.RequireServerUsage || endpoint.VerifyX509Name.Mode != X509CommonName ||
				cfg.Credentials == nil && auth.Credentials == nil ||
				cfg.AdvertiseDNS || cfg.Authentication.Interactive()) {
				return nil, configError("fixed DATA_V1 policy")
			}
			offer = []string{fixed}
		}
		if settings == nil {
			continue
		}
		if _, err := protection.ControlChunkSize(cfg.MaxPacketSize); err != nil {
			return nil, configError("control frame size")
		}
		peer := tlscontrol.PeerConfigWithTrust(settings, endpoint.ServerName, string(endpoint.VerifyX509Name.Mode),
			endpoint.VerifyX509Name.Value, cfg.TLS.RequireServerUsage, trust)
		opts := limits
		if endpoint.TunnelMTU != 0 {
			opts.TunnelMTU = endpoint.TunnelMTU
		}
		if opts.TunnelMTU != 0 && endpoint.ExpressVPNFragmentSize == 0 &&
			opts.MaxPacketSize-data.Overhead < 68 {
			return nil, configError("tunnel MTU")
		}
		opts.TLS = tlscontrol.Options{TLS: peer, Digest: wireDigest, Ciphers: offer, PushPolicy: cfg.PushPolicy,
			Interaction: auth, ExitNotify: (cfg.ExplicitExitNotify || endpoint.ExplicitExitNotify) && strings.HasPrefix(endpoint.Network, "udp"),
			TunnelMTU: opts.TunnelMTU, FixedAEAD: endpoint.FixedAEAD, FixedDataV1: endpoint.FixedAEADDataV1,
			AllowLZOStub: endpoint.ExpressVPNFragmentSize != 0, AdvertiseDNS: cfg.AdvertiseDNS}
		opts.Protection = protection
		opts.FragmentSize = endpoint.ExpressVPNFragmentSize
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
		opts.TLS.ServerPollTimeout = endpoint.ServerPollTimeout
		opts.TLS.Auth = tlscontrol.NewAuthentication(user)
		link, err := session.Open(ctx, packets, opts)
		if err != nil {
			return nil, setControlError(err)
		}
		return link, nil
	}
}

func setControlError(err error) error {
	failure := &Error{Op: "handshake", Code: packetErrorCode(err, CodeProtocol)}
	if errors.Is(err, tlscontrol.ErrPeerRestartSame) {
		return restartSameError{failure}
	}
	return failure
}
