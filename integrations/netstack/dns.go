package netstack

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"slices"
	"time"
)

const maxDNSPacket = 4096

var ErrDNS = errors.New("invalid or unavailable userspace DNS exchange")

// ExchangeDNS sends a bounded DNS wire query to an explicitly configured
// resolver. A truncated UDP reply retries over TCP at the same endpoint.
// The caller supplies the query and interprets the DNS response.
func (a *Adapter) ExchangeDNS(ctx context.Context, server netip.AddrPort, request []byte) ([]byte, error) {
	if !slices.Contains(a.dns, server) || len(request) < 12 || len(request) > maxDNSPacket ||
		request[2]&0x80 != 0 || binary.BigEndian.Uint16(request[4:6]) != 1 {
		return nil, ErrDNS
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	response, err := a.dnsExchange(ctx, "udp", server, request)
	if err != nil {
		return nil, err
	}
	if response[2]&0x02 != 0 {
		response, err = a.dnsExchange(ctx, "tcp", server, request)
		if err == nil && response[2]&0x02 != 0 {
			return nil, ErrDNS
		}
	}
	return response, err
}

func (a *Adapter) dnsExchange(ctx context.Context, network string, server netip.AddrPort, request []byte) ([]byte, error) {
	conn, err := a.dial(ctx, network, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	wire := request
	if network == "tcp" {
		wire = make([]byte, 2, 2+len(request))
		binary.BigEndian.PutUint16(wire, uint16(len(request)))
		wire = append(wire, request...)
	}
	if n, err := conn.Write(wire); err != nil || n != len(wire) {
		return nil, a.dnsFailure(ctx)
	}
	var response []byte
	if network == "tcp" {
		var frame [2]byte
		if _, err := io.ReadFull(conn, frame[:]); err != nil {
			return nil, a.dnsFailure(ctx)
		}
		size := int(binary.BigEndian.Uint16(frame[:]))
		if size < 12 || size > maxDNSPacket {
			return nil, ErrDNS
		}
		response = make([]byte, size)
		if _, err := io.ReadFull(conn, response); err != nil {
			return nil, a.dnsFailure(ctx)
		}
	} else {
		buf := make([]byte, maxDNSPacket+1)
		n, err := conn.Read(buf)
		if err != nil {
			return nil, a.dnsFailure(ctx)
		}
		if n < 12 || n > maxDNSPacket {
			return nil, ErrDNS
		}
		response = buf[:n]
	}
	if binary.BigEndian.Uint16(response) != binary.BigEndian.Uint16(request) ||
		response[2]&0x80 == 0 || response[2]&0x78 != request[2]&0x78 {
		return nil, ErrDNS
	}
	return response, ctx.Err()
}

func (a *Adapter) dnsFailure(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := a.life.Err(); err != nil {
		return err
	}
	return ErrDNS
}
