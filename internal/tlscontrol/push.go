package tlscontrol

import (
	"bytes"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Negotiation is the authenticated subset needed by the data channel and
// embedding application.
type Negotiation struct {
	Cipher     string
	PeerID     uint32
	TLSVersion uint16

	PingInterval time.Duration
	PingTimeout  time.Duration
	PingExit     bool
	TunnelIP     netip.Addr
	TunnelIPv6   netip.Prefix
}

type pushState struct {
	Negotiation
	allowed   []string
	havePeer  bool
	exporter  bool
	continued bool
	parts     int
	total     int
	token     []byte
	tokenUser string
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
	if p.continued != (marker == "1") || !p.exporter || !p.havePeer || p.Cipher == "" {
		return false, ErrNegotiation
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
	case "key-derivation", "protocol-flags":
		// We advertise the exporter, and no other optional protocol flags.
		if string(arg) != "tls-ekm" || p.exporter {
			return ErrNegotiation
		}
		p.exporter = true
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
		if err != nil || seconds == 0 {
			return ErrNegotiation
		}
		value := time.Duration(seconds) * time.Second
		if name == "ping" {
			p.PingInterval = value
		} else {
			exit := name == "ping-exit"
			if p.PingTimeout != 0 && p.PingExit != exit {
				return ErrNegotiation
			}
			p.PingTimeout, p.PingExit = value, exit
		}
	case "tun-ipv6":
		if len(arg) != 0 {
			return ErrNegotiation
		}
	case "topology":
		switch string(arg) {
		case "subnet", "net30", "p2p":
		default:
			return ErrNegotiation
		}
	case "ifconfig", "ifconfig-ipv6":
		fields := strings.Fields(string(arg))
		if len(fields) != 2 {
			return ErrNegotiation
		}
		remote, err := netip.ParseAddr(fields[1])
		if err != nil {
			return ErrNegotiation
		}
		if name == "ifconfig-ipv6" {
			local, err := netip.ParsePrefix(fields[0])
			if err != nil || !local.Addr().Is6() || !remote.Is6() || p.TunnelIPv6.IsValid() {
				return ErrNegotiation
			}
			p.TunnelIPv6 = local
		} else {
			local, err := netip.ParseAddr(fields[0])
			if err != nil || !local.Is4() || !remote.Is4() || p.TunnelIP.IsValid() {
				return ErrNegotiation
			}
			p.TunnelIP = local
		}
	case "route", "route-ipv6", "route-gateway", "redirect-gateway", "dhcp-option",
		"block-outside-dns", "tun-mtu":
		// This stage does not export or apply advisory network settings.
		// Recognize the documented fields and bound their input.
		if len(arg) > 1024 || !validKeyString(string(arg)) {
			return ErrNegotiation
		}
	default:
		return ErrNegotiation
	}
	return nil
}
