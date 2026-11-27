package tlscontrol

import (
	"bytes"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/crypt"
	"github.com/hamedsanaei/openvpn-go/tunnel"
)

// Negotiation is the authenticated subset needed by the data channel and
// embedding application.
type Negotiation struct {
	Cipher     string
	PeerID     uint32
	TLSVersion uint16
	Derivation crypt.Derivation

	PingInterval time.Duration
	PingTimeout  time.Duration
	PingExit     bool
	ExitNotify   bool
	Tunnel       tunnel.Configuration
	PacketMTU    int
}

type pushState struct {
	Negotiation
	allowed         []string
	fixedAEAD       string
	havePeer        bool
	exporter        bool
	allowExit       bool
	haveFlags       bool
	havePing        bool
	havePingTimeout bool
	allowLZOStub    bool
	haveLZOStub     bool
	haveRouteMetric bool
	routeMetric     uint32
	continued       bool
	parts           int
	total           int
	token           []byte
	tokenUser       string
	policy          tunnel.PushPolicy
	ipv4, ipv4Param netip.Addr
	routes          []tunnel.Route
	dns             tunnel.DNSConfig
	legacyDNS       []netip.AddrPort
	modernSearch    []string
	dnsGroups       map[uint8]tunnel.DNSServer
}

func (p *pushState) add(message []byte) (bool, error) {
	p.parts++
	p.total += len(message)
	if p.parts > 16 || p.total > maxCommand {
		return false, ErrNegotiation
	}
	command, options, ok := bytes.Cut(message, []byte{','})
	if !bytes.Equal(command, []byte("PUSH_REPLY")) {
		return false, unexpectedCommand(message)
	}
	if !ok {
		return false, ErrNegotiation
	}

	marker := ""
	for opt := range bytes.SplitSeq(options, []byte{','}) {
		if marker != "" {
			return false, ErrNegotiation
		}
		name, args, _ := bytes.Cut(opt, []byte{' '})
		if string(name) == "push-continuation" {
			marker = string(args)
			if marker != "1" && marker != "2" {
				return false, ErrNegotiation
			}
		} else if err := p.option(string(name), args); err != nil {
			return false, err
		}
	}

	if marker == "2" {
		p.continued = true
		return false, nil
	}
	if p.continued != (marker == "1") || !p.havePeer {
		return false, ErrNegotiation
	}
	if p.fixedAEAD != "" {
		if p.exporter || (p.Cipher != "" && p.Cipher != p.fixedAEAD) {
			return false, ErrNegotiation
		}
		p.Cipher, p.Derivation = p.fixedAEAD, crypt.ClassicKM2
	} else {
		if !p.exporter || p.Cipher == "" {
			return false, ErrNegotiation
		}
		p.Derivation = crypt.TLSExporter
	}
	if err := p.finishTunnel(); err != nil {
		return false, err
	}
	return true, nil
}

func (p *pushState) option(name string, arg []byte) error {
	switch name {
	case "cipher":
		i := slices.Index(p.allowed, string(arg))
		if i < 0 || p.Cipher != "" {
			return ErrNegotiation
		}
		p.Cipher = p.allowed[i]
	case "peer-id":
		id, err := strconv.ParseUint(string(arg), 10, 24)
		if p.havePeer || err != nil || id == 0xffffff {
			return ErrNegotiation
		}
		p.PeerID, p.havePeer = uint32(id), true
	case "key-derivation":
		if string(arg) != "tls-ekm" || p.exporter {
			return ErrNegotiation
		}
		p.exporter = true
	case "protocol-flags":
		if p.haveFlags {
			return ErrNegotiation
		}
		p.haveFlags = true
		for flag := range bytes.SplitSeq(arg, []byte{' '}) {
			switch {
			case string(flag) == "tls-ekm" && !p.exporter:
				p.exporter = true
			case string(flag) == "cc-exit" && p.allowExit && !p.ExitNotify:
				p.ExitNotify = true
			default:
				return ErrNegotiation
			}
		}
	case "explicit-exit-notify":
		// Legacy exit retries are optional. Only an authenticated
		// cc-exit flag can select reliable control-channel notification.
		if len(arg) != 0 {
			if _, err := strconv.ParseUint(string(arg), 10, 8); err != nil {
				return ErrNegotiation
			}
		}
	case "socket-flags":
		if string(arg) != "TCP_NODELAY" {
			return ErrNegotiation
		}
	case "sndbuf", "rcvbuf":
		// The application owns transport socket settings. Validate the
		// supplied byte count without allocating or resizing buffers.
		if _, err := strconv.ParseUint(string(arg), 10, 31); err != nil {
			return ErrNegotiation
		}
	case "comp-lzo":
		if !p.allowLZOStub || p.haveLZOStub || string(arg) != "no" {
			return ErrNegotiation
		}
		p.haveLZOStub = true
	case "auth-token":
		if len(p.token) != 0 || len(arg) == 0 || !validKeyString(string(arg)) {
			return ErrNegotiation
		}
		p.token = bytes.Clone(arg)
	case "auth-token-user":
		if p.tokenUser != "" {
			return ErrNegotiation
		}
		user, err := tokenUsername(arg)
		if err != nil {
			return err
		}
		p.tokenUser = user
	case "ping", "ping-restart", "ping-exit":
		seconds, err := strconv.ParseUint(string(arg), 10, 16)
		if err != nil {
			return ErrNegotiation
		}
		value := time.Duration(seconds) * time.Second
		if name == "ping" {
			if p.havePing {
				return ErrNegotiation
			}
			p.PingInterval, p.havePing = value, true
		} else {
			exit := name == "ping-exit"
			if p.havePingTimeout {
				return ErrNegotiation
			}
			p.PingTimeout, p.PingExit, p.havePingTimeout = value, exit && value != 0, true
		}
	default:
		return p.tunnelOption(name, string(arg))
	}
	return nil
}
