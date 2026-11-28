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
	epoch   uint64
	sent    uint32
	replay  replay
	expires time.Time
}

// Channel holds the current data keys and at most one receive-only retiring
// generation. Its caller serializes access by the session's I/O workers.
type Channel struct {
	peerID   uint32
	dataV1   bool
	udp      bool
	current  *generation
	retiring *generation
	nonce    [12]byte
}

func NewChannel(peerID uint32, udp bool, keys crypt.DataKeys) (*Channel, error) {
	return NewChannelForFormat(peerID, udp, keys, false)
}

func NewChannelForFormat(peerID uint32, udp bool, keys crypt.DataKeys, dataV1 bool) (*Channel, error) {
	if peerID >= 0xffffff || dataV1 && peerID != 0 {
		return nil, ErrPacket
	}
	return &Channel{peerID: peerID, udp: udp, dataV1: dataV1, current: &generation{keys: keys, epoch: 1}}, nil
}

func NextKeyID(id uint8) uint8 { return id%7 + 1 }

func (c *Channel) KeyID() uint8 { return c.current.id }

func (c *Channel) RekeyDue() bool {
	return c.RekeyDueWithHeadroom(rekeyHeadroom, rekeyHeadroom)
}

// KeyUsage counts consumed transmit nonces and the highest authenticated
// receive packet ID in the current local epoch.
type KeyUsage struct {
	Epoch                 uint64
	Sent, Received, Limit uint32
}

func (c *Channel) KeyUsage() KeyUsage {
	g := c.current
	return KeyUsage{Epoch: g.epoch, Sent: g.sent, Received: g.replay.high, Limit: g.keys.PacketLimit}
}

func (c *Channel) RekeyDueWithHeadroom(send, receive uint32) bool {
	g := c.current
	return g.keys.PacketLimit-g.sent <= max(rekeyHeadroom, send) ||
		g.keys.PacketLimit-g.replay.high <= max(rekeyHeadroom, receive)
}

func (c *Channel) Promote(id uint8, keys crypt.DataKeys, expires time.Time) error {
	if id != NextKeyID(c.current.id) {
		return ErrKeyID
	}
	c.current.expires = expires
	c.retiring = c.current
	c.current = &generation{keys: keys, id: id, epoch: c.current.epoch + 1}
	return nil
}

func (c *Channel) Retire(now time.Time) {
	if c.retiring != nil && !now.Before(c.retiring.expires) {
		c.retiring = nil
	}
}

func (c *Channel) Seal(payload []byte) ([]byte, error) {
	return c.SealInto(nil, payload)
}

// SealInto uses dst as scratch for the complete frame. The returned frame
// replaces dst and may alias its capacity. dst must not alias payload.
func (c *Channel) SealInto(dst, payload []byte) ([]byte, error) {
	if len(payload) == 0 {
		return nil, ErrPacket
	}
	g := c.current
	if g.sent >= g.keys.PacketLimit {
		return nil, ErrKeyLimit
	}
	g.sent++
	prefix, pidOffset, aadOffset := additionalSize, 4, 0
	if c.dataV1 {
		prefix, pidOffset, aadOffset = 5, 1, 1
	}
	overhead := prefix + tagSize
	if cap(dst) < overhead+len(payload) {
		dst = make([]byte, 0, overhead+len(payload))
	}
	packet := dst[:prefix]
	if c.dataV1 {
		packet[0] = byte(wire.DataV1)<<3 | g.id
	} else {
		binary.BigEndian.PutUint32(packet, uint32(uint8(wire.DataV2)<<3|g.id)<<24|c.peerID)
	}
	binary.BigEndian.PutUint32(packet[pidOffset:], g.sent)
	c.setNonce(g.sent, g.keys.Send.ImplicitIV)
	packet = g.keys.Send.AEAD.Seal(packet, c.nonce[:], payload, packet[aadOffset:prefix])
	// Go's AEAD appends its tag. OpenVPN transmits it before ciphertext.
	var tag [tagSize]byte
	copy(tag[:], packet[len(packet)-tagSize:])
	copy(packet[overhead:], packet[prefix:len(packet)-tagSize])
	copy(packet[prefix:overhead], tag[:])
	return packet, nil
}

func (c *Channel) Open(packet []byte, now time.Time) ([]byte, error) {
	plaintext, _, err := c.OpenWithEpoch(packet, now)
	return plaintext, err
}

// HasEpoch reports whether a local key generation can still receive data.
func (c *Channel) HasEpoch(epoch uint64) bool {
	return c.current.epoch == epoch || c.retiring != nil && c.retiring.epoch == epoch
}

// OpenWithEpoch returns the local identity of the authenticated receive key.
func (c *Channel) OpenWithEpoch(packet []byte, now time.Time) ([]byte, uint64, error) {
	return c.open(packet, now, false)
}

// OpenOwned consumes an owned frame. On success the plaintext aliases the
// input. The frame header remains intact for authenticated fragment handling.
func (c *Channel) OpenOwned(packet []byte, now time.Time) ([]byte, uint64, error) {
	return c.open(packet, now, true)
}

func (c *Channel) open(packet []byte, now time.Time, owned bool) ([]byte, uint64, error) {
	prefix, pidOffset, aadOffset := additionalSize, 4, 0
	opcode := wire.DataV2
	if c.dataV1 {
		prefix, pidOffset, aadOffset, opcode = 5, 1, 1, wire.DataV1
	}
	overhead := prefix + tagSize
	if len(packet) <= overhead || wire.Opcode(packet[0]>>3) != opcode ||
		!c.dataV1 && binary.BigEndian.Uint32(packet)&0xffffff != c.peerID {
		return nil, 0, ErrPacket
	}
	c.Retire(now)
	id := packet[0] & 7
	g := c.current
	if id != g.id {
		g = c.retiring
		if g == nil || g.id != id {
			return nil, 0, ErrKeyID
		}
	}
	pid := binary.BigEndian.Uint32(packet[pidOffset:])
	if pid > g.keys.PacketLimit || !g.replay.admissible(pid, c.udp, now) {
		return nil, 0, ErrPacket
	}
	var tag [tagSize]byte
	copy(tag[:], packet[prefix:overhead])
	sealed := packet[prefix:]
	if !owned {
		sealed = make([]byte, len(sealed))
	}
	n := copy(sealed, packet[overhead:])
	copy(sealed[n:], tag[:])
	c.setNonce(pid, g.keys.Receive.ImplicitIV)
	plain, err := g.keys.Receive.AEAD.Open(sealed[:0], c.nonce[:], sealed, packet[aadOffset:prefix])
	if err != nil {
		clear(sealed)
		return nil, 0, ErrPacket
	}
	g.replay.commit(pid, c.udp, now)
	return plain, g.epoch, nil
}

func (c *Channel) setNonce(id uint32, implicit [8]byte) {
	binary.BigEndian.PutUint32(c.nonce[:4], id)
	copy(c.nonce[4:], implicit[:])
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
