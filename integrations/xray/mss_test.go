package xray

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestMSSClamp(t *testing.T) {
	for _, tc := range []struct {
		name string
		v6   bool
		odd  bool
		frag bool
		want uint16
	}{
		{"IPv4", false, false, false, 1260},
		{"IPv4 odd TCP option offset", false, true, false, 1260},
		{"IPv4 fragment", false, false, true, 0},
		{"IPv6 extension and odd TCP option offset", true, true, false, 1240},
		{"IPv6 fragment", true, false, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ipHeader := 20
			if tc.v6 {
				ipHeader = 48
			}
			packet := make([]byte, ipHeader+28)
			if tc.v6 {
				packet[0], packet[6], packet[40] = 0x60, 60, 6
				binary.BigEndian.PutUint16(packet[4:], uint16(len(packet)-40))
				if tc.frag {
					packet[6] = 44
				}
			} else {
				packet[0], packet[9] = 0x45, 6
				binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
				if tc.frag {
					packet[6] = 0x20
				}
			}
			tcp := packet[ipHeader:]
			tcp[12], tcp[13] = 0x70, 0x02
			option := 20
			if tc.odd {
				tcp[option] = 1
				option++
			}
			tcp[option], tcp[option+1] = 2, 4
			binary.BigEndian.PutUint16(tcp[option+2:], 1460)
			// The fixture has all-zero addresses. Its pseudo-header sum
			// then consists of the upper-layer length and protocol number.
			binary.BigEndian.PutUint16(tcp[16:], ^tcpSum(tcp))
			before := bytes.Clone(packet)
			offset, value := mssChange(packet, 1300)
			if value != tc.want {
				t.Fatalf("replacement = %d, want %d", value, tc.want)
			}
			if offset != 0 {
				setMSS(packet, offset, value)
				if !bytes.Equal(before[:ipHeader], packet[:ipHeader]) ||
					binary.BigEndian.Uint16(tcp[option+2:]) != tc.want || tcpSum(tcp) != 0xffff {
					t.Fatal("invalid TCP checksum or changed IP header")
				}
			} else if !bytes.Equal(before, packet) {
				t.Fatal("unsupported packet was modified")
			}
		})
	}
}

func tcpSum(payload []byte) uint16 {
	sum := uint32(len(payload) + 6)
	for i := 0; i < len(payload); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(payload[i:]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum)
}
