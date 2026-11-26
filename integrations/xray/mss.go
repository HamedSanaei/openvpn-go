package xray

import (
	"context"
	"encoding/binary"
	"slices"
	"sync/atomic"

	"github.com/hamedsanaei/openvpn-go/tunnel"
)

type mssDevice struct {
	tunnel.PacketConn
	mtu atomic.Int32
}

func (d *mssDevice) ReadPacket(ctx context.Context, dst []byte) (int, error) {
	n, err := d.PacketConn.ReadPacket(ctx, dst)
	if err == nil && n > 0 && n <= len(dst) {
		if offset, limit := mssChange(dst[:n], int(d.mtu.Load())); offset != 0 {
			setMSS(dst[:n], offset, limit)
		}
	}
	return n, err
}

func (d *mssDevice) WritePacket(ctx context.Context, packet []byte) error {
	if offset, limit := mssChange(packet, int(d.mtu.Load())); offset != 0 {
		packet = slices.Clone(packet)
		setMSS(packet, offset, limit)
	}
	return d.PacketConn.WritePacket(ctx, packet)
}

// mssChange returns the TCP header offset and replacement value. Only
// complete SYN/SYN-ACK packets with one well-formed MSS can be rewritten.
func mssChange(packet []byte, mtu int) (int, uint16) {
	if mtu < 68 || len(packet) < 40 {
		return 0, 0
	}
	var tcpStart, limit int
	switch packet[0] >> 4 {
	case 4:
		tcpStart = int(packet[0]&15) * 4
		if tcpStart < 20 || tcpStart > len(packet)-20 || packet[9] != 6 ||
			int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) ||
			binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
			return 0, 0
		}
		limit = mtu - 40
	case 6:
		if len(packet) < 60 || mtu < 1280 || int(binary.BigEndian.Uint16(packet[4:6]))+40 != len(packet) {
			return 0, 0
		}
		tcpStart = ipv6TCP(packet)
		if tcpStart == 0 {
			return 0, 0
		}
		limit = mtu - 60
	default:
		return 0, 0
	}
	tcp := packet[tcpStart:]
	if tcp[13]&0x02 == 0 {
		return 0, 0
	}
	offset := mssOffset(tcp)
	if offset == 0 || int(binary.BigEndian.Uint16(tcp[offset:])) <= limit {
		return 0, 0
	}
	return tcpStart, uint16(limit)
}

func ipv6TCP(packet []byte) int {
	offset, next := 40, packet[6]
	for range 8 {
		if offset > len(packet)-20 {
			return 0
		}
		switch next {
		case 6:
			return offset
		case 0, 43, 60: // Hop-by-Hop, Routing, Destination Options
			next, offset = packet[offset], offset+(int(packet[offset+1])+1)*8
		default: // Includes Fragment, AH, and ESP.
			return 0
		}
	}
	return 0
}

func mssOffset(tcp []byte) int {
	end := int(tcp[12]>>4) * 4
	if end < 20 || end > len(tcp) {
		return 0
	}
	mss := 0
	for i := 20; i < end; {
		kind := tcp[i]
		switch kind {
		case 0:
			return mss
		case 1:
			i++
			continue
		case 19, 29: // TCP-MD5 and TCP-AO authenticate the header.
			return 0
		}
		if i+1 >= end {
			return 0
		}
		length := int(tcp[i+1])
		if length < 2 || i+length > end {
			return 0
		}
		if kind == 2 {
			if mss != 0 || length != 4 {
				return 0
			}
			mss = i + 2
		}
		i += length
	}
	return mss
}

func setMSS(packet []byte, tcpStart int, replacement uint16) {
	tcp := packet[tcpStart:]
	offset := mssOffset(tcp)
	old := binary.BigEndian.Uint16(tcp[offset:])
	binary.BigEndian.PutUint16(tcp[offset:], replacement)
	if offset%2 != 0 {
		old = old<<8 | old>>8
		replacement = replacement<<8 | replacement>>8
	}
	sum := uint32(^binary.BigEndian.Uint16(tcp[16:18])) + uint32(^old) + uint32(replacement)
	sum = (sum & 0xffff) + (sum >> 16)
	binary.BigEndian.PutUint16(tcp[16:18], ^uint16((sum&0xffff)+(sum>>16)))
}
