package data

import (
	"bytes"
	"encoding/binary"
	"errors"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/crypt"
	"github.com/hamedsanaei/openvpn-go/internal/wire"
)

const (
	additionalSize = 8
	tagSize        = 16
	Overhead       = additionalSize + tagSize
	rekeyHeadroom  = 1024
)

var (
	ErrPacket   = errors.New("invalid OpenVPN data packet")
	ErrKeyLimit = errors.New("OpenVPN data key packet limit reached")
	ErrKeyID    = errors.New("unexpected OpenVPN data key ID")
)

type generation struct {
	keys    crypt.DataKeys
	id      uint8
	sent    uint32
	replay  replay
	expires time.Time
}

// Channel holds the current data keys and at most one receive-only retiring
// generation. Its caller serializes access by the session's I/O workers.
type Channel struct {
	peerID   uint32
	udp      bool
	current  *generation
	retiring *generation
}

func NewChannel(peerID uint32, udp bool, keys crypt.DataKeys) (*Channel, error) {
	if peerID >= 0xffffff {
		return nil, ErrPacket
	}
	return &Channel{peerID: peerID, udp: udp, current: &generation{keys: keys}}, nil
}

func NextKeyID(id uint8) uint8 { return id%7 + 1 }

func (c *Channel) KeyID() uint8 { return c.current.id }

func (c *Channel) RekeyDue() bool {
	g := c.current
	return g.keys.PacketLimit-g.sent <= rekeyHeadroom ||
		g.keys.PacketLimit-g.replay.high <= rekeyHeadroom
}

func (c *Channel) Promote(id uint8, keys crypt.DataKeys, expires time.Time) error {
	if id != NextKeyID(c.current.id) {
		return ErrKeyID
	}
	c.current.expires = expires
	c.retiring = c.current
	c.current = &generation{keys: keys, id: id}
	return nil
}

func (c *Channel) Retire(now time.Time) {
	if c.retiring != nil && !now.Before(c.retiring.expires) {
		c.retiring = nil
	}
}

func (c *Channel) Seal(payload []byte) ([]byte, error) {
	if len(payload) == 0 {
		return nil, ErrPacket
	}
	g := c.current
	if g.sent >= g.keys.PacketLimit {
		return nil, ErrKeyLimit
	}
	g.sent++
	packet := make([]byte, additionalSize, Overhead+len(payload))
	binary.BigEndian.PutUint32(packet, uint32(uint8(wire.DataV2)<<3|g.id)<<24|c.peerID)
	binary.BigEndian.PutUint32(packet[4:], g.sent)
	iv := nonce(g.sent, g.keys.Send.ImplicitIV)
	packet = g.keys.Send.AEAD.Seal(packet, iv[:], payload, packet[:additionalSize])
	// Go's AEAD appends its tag. OpenVPN transmits it before ciphertext.
	var tag [tagSize]byte
	copy(tag[:], packet[len(packet)-tagSize:])
	copy(packet[Overhead:], packet[additionalSize:len(packet)-tagSize])
	copy(packet[additionalSize:Overhead], tag[:])
	return packet, nil
}

func (c *Channel) Open(packet []byte, now time.Time) ([]byte, error) {
	if len(packet) <= Overhead || wire.Opcode(packet[0]>>3) != wire.DataV2 ||
		binary.BigEndian.Uint32(packet)&0xffffff != c.peerID {
		return nil, ErrPacket
	}
	c.Retire(now)
	id := packet[0] & 7
	g := c.current
	if id != g.id {
		g = c.retiring
		if g == nil || g.id != id {
			return nil, ErrKeyID
		}
	}
	pid := binary.BigEndian.Uint32(packet[4:])
	if pid > g.keys.PacketLimit || !g.replay.admissible(pid, c.udp, now) {
		return nil, ErrPacket
	}
	iv := nonce(pid, g.keys.Receive.ImplicitIV)
	sealed := make([]byte, 0, len(packet)-additionalSize)
	sealed = append(sealed, packet[Overhead:]...)
	sealed = append(sealed, packet[additionalSize:Overhead]...)
	plain, err := g.keys.Receive.AEAD.Open(sealed[:0], iv[:], sealed, packet[:additionalSize])
	if err != nil {
		return nil, ErrPacket
	}
	g.replay.commit(pid, c.udp, now)
	return plain, nil
}

func nonce(id uint32, implicit [8]byte) [12]byte {
	var value [12]byte
	binary.BigEndian.PutUint32(value[:4], id)
	copy(value[4:], implicit[:])
	return value
}

// OpenVPN keepalives are encrypted data packets with this exact payload.
const Keepalive = "\x2a\x18\x7b\xf3\x64\x1e\xb4\xcb\x07\xed\x2d\x0a\x98\x1f\xc7\x48"

func IsKeepalive(packet []byte) bool { return bytes.Equal(packet, []byte(Keepalive)) }

// IsIP checks the minimum IP header and the declared length of a TUN packet.
func IsIP(packet []byte) bool {
	if len(packet) < 20 {
		return false
	}
	switch packet[0] >> 4 {
	case 4:
		ihl := int(packet[0]&15) * 4
		return ihl >= 20 && ihl <= len(packet) && int(binary.BigEndian.Uint16(packet[2:4])) == len(packet)
	case 6:
		return len(packet) >= 40 && int(binary.BigEndian.Uint16(packet[4:6]))+40 == len(packet)
	default:
		return false
	}
}
