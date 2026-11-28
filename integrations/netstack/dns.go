package netstack

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"time"
)

const maxDNSPacket = 4096

var ErrDNS = errors.New("invalid or unavailable userspace DNS exchange")

// ExchangeDNS sends a bounded DNS wire query to an explicitly configured
// resolver. A truncated UDP reply retries over TCP at the same endpoint.
// The reply must repeat the query's single question. The caller interprets
// the response records and DNS response code.
func (a *Adapter) ExchangeDNS(ctx context.Context, server netip.AddrPort, request []byte) ([]byte, error) {
	if !slices.Contains(a.dns, server) || len(request) < 12 || len(request) > maxDNSPacket ||
		request[2]&0x80 != 0 {
		return nil, ErrDNS
	}
	question, ok := dnsQuestionOf(request)
	if !ok {
		return nil, ErrDNS
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	response, err := a.dnsExchange(ctx, "udp", server, request, question)
	if err != nil {
		return nil, err
	}
	if response[2]&0x02 != 0 {
		response, err = a.dnsExchange(ctx, "tcp", server, request, question)
		if err == nil && response[2]&0x02 != 0 {
			return nil, ErrDNS
		}
	}
	return response, err
}

func (a *Adapter) dnsExchange(ctx context.Context, network string, server netip.AddrPort, request []byte, question dnsQuestion) ([]byte, error) {
	conn, err := a.dial(ctx, network, server)
	if err != nil {
		if errors.Is(err, ErrSocketLimit) || errors.Is(err, net.ErrClosed) {
			return nil, err
		}
		return nil, a.dnsFailure(ctx, err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, a.dnsFailure(ctx, err)
	}
	wire := request
	if network == "tcp" {
		wire = make([]byte, 2, 2+len(request))
		binary.BigEndian.PutUint16(wire, uint16(len(request)))
		wire = append(wire, request...)
	}
	if n, err := conn.Write(wire); err != nil || n != len(wire) {
		return nil, a.dnsFailure(ctx, err)
	}
	var response []byte
	if network == "tcp" {
		var frame [2]byte
		if _, err := io.ReadFull(conn, frame[:]); err != nil {
			return nil, a.dnsFailure(ctx, err)
		}
		size := int(binary.BigEndian.Uint16(frame[:]))
		if size < 12 || size > maxDNSPacket {
			return nil, ErrDNS
		}
		response = make([]byte, size)
		if _, err := io.ReadFull(conn, response); err != nil {
			return nil, a.dnsFailure(ctx, err)
		}
	} else {
		buf := make([]byte, maxDNSPacket+1)
		n, err := conn.Read(buf)
		if err != nil {
			return nil, a.dnsFailure(ctx, err)
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
	if actual, ok := dnsQuestionOf(response); !ok || actual != question {
		return nil, ErrDNS
	}
	return response, ctx.Err()
}

func (a *Adapter) dnsFailure(ctx context.Context, cause error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := a.life.Err(); err != nil {
		return err
	}
	deadline, hasDeadline := ctx.Deadline()
	timeout, ok := errors.AsType[net.Error](cause)
	if errors.Is(cause, context.DeadlineExceeded) || ok && timeout.Timeout() ||
		hasDeadline && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return ErrDNS
}

type dnsQuestion struct {
	name  [255]byte
	qtype uint16
	class uint16
}

func dnsQuestionOf(message []byte) (dnsQuestion, bool) {
	var question dnsQuestion
	if len(message) < 12 || binary.BigEndian.Uint16(message[4:6]) != 1 {
		return question, false
	}
	// Compression pointers point backwards. Keep the offset to QTYPE
	// after the encoded name while bounding the expanded wire name.
	pos, size, tail, ceiling := 12, 0, 0, len(message)
	for {
		if pos >= ceiling {
			return question, false
		}
		label := int(message[pos])
		switch {
		case label == 0:
			if tail == 0 {
				tail = pos + 1
			}
			if tail+4 > len(message) {
				return question, false
			}
			question.qtype = binary.BigEndian.Uint16(message[tail:])
			question.class = binary.BigEndian.Uint16(message[tail+2:])
			return question, true
		case label&0xc0 == 0xc0:
			if pos+1 >= ceiling {
				return question, false
			}
			pointer := (label&0x3f)<<8 | int(message[pos+1])
			if pointer < 12 || pointer >= pos {
				return question, false
			}
			if tail == 0 {
				tail = pos + 2
			}
			ceiling, pos = pos, pointer
		case label > 63 || pos+1+label > ceiling || size+1+label >= len(question.name):
			return question, false
		default:
			question.name[size] = byte(label)
			pos++
			size++
			for _, ch := range message[pos : pos+label] {
				if 'A' <= ch && ch <= 'Z' {
					ch += 'a' - 'A'
				}
				question.name[size] = ch
				size++
			}
			pos += label
		}
	}
}
