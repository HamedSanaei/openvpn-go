package wire

import (
	"encoding/binary"
	"errors"
)

const (
	// PrefixSize is the size of the opcode/key ID and local session ID.
	PrefixSize = 9
	// MaxACKs is the maximum number of packet IDs in a control ACK list.
	MaxACKs = 8
)

var ErrPacket = errors.New("invalid OpenVPN control packet")

type Opcode uint8

const (
	SoftReset   Opcode = 3
	Control     Opcode = 4
	ACK         Opcode = 5
	DataV1      Opcode = 6
	ClientReset Opcode = 7
	ServerReset Opcode = 8
	DataV2      Opcode = 9
	ClientV3    Opcode = 10
	WrappedKey  Opcode = 11
)

type Header struct {
	Opcode Opcode
	KeyID  uint8
}

func (h Header) Byte() (byte, error) {
	if h.Opcode < SoftReset || h.Opcode > WrappedKey || h.KeyID > 7 {
		return 0, ErrPacket
	}
	return byte(h.Opcode)<<3 | h.KeyID, nil
}

func ParseHeader(packet []byte) (Header, error) {
	if len(packet) == 0 {
		return Header{}, ErrPacket
	}
	h := Header{Opcode: Opcode(packet[0] >> 3), KeyID: packet[0] & 7}
	if h.Opcode < SoftReset || h.Opcode > WrappedKey {
		return Header{}, ErrPacket
	}
	return h, nil
}

func (h Header) IsData() bool { return h.Opcode == DataV1 || h.Opcode == DataV2 }

type SessionID [8]byte

type ControlPacket struct {
	Header
	Sender    SessionID
	ACKs      [MaxACKs]uint32
	ACKCount  int
	ACKTarget SessionID
	ID        uint32
	// Payload aliases the input of ParseControl.
	Payload []byte
}

func (p ControlPacket) AppendPrefix(dst []byte) ([]byte, error) {
	header, err := p.Header.Byte()
	if err != nil || p.IsData() {
		return nil, ErrPacket
	}
	dst = append(dst, header)
	return append(dst, p.Sender[:]...), nil
}

// AppendBody writes the fields inside the optional control wrapper.
func (p ControlPacket) AppendBody(dst []byte) ([]byte, error) {
	if p.ACKCount < 0 || p.ACKCount > MaxACKs ||
		(p.Opcode == ACK && (p.ACKCount == 0 || len(p.Payload) != 0)) {
		return nil, ErrPacket
	}
	dst = append(dst, byte(p.ACKCount))
	for _, id := range p.ACKs[:p.ACKCount] {
		dst = binary.BigEndian.AppendUint32(dst, id)
	}
	if p.ACKCount != 0 {
		dst = append(dst, p.ACKTarget[:]...)
	}
	if p.Opcode != ACK {
		dst = binary.BigEndian.AppendUint32(dst, p.ID)
	}
	return append(dst, p.Payload...), nil
}

// ParseControl combines the clear prefix and the validated clear body.
func ParseControl(prefix, body []byte) (ControlPacket, error) {
	header, err := ParseHeader(prefix)
	if err != nil || header.IsData() || len(prefix) != PrefixSize || len(body) == 0 {
		return ControlPacket{}, ErrPacket
	}
	var p ControlPacket
	p.Header = header
	copy(p.Sender[:], prefix[1:])
	p.ACKCount = int(body[0])
	body = body[1:]

	if p.ACKCount > MaxACKs {
		return ControlPacket{}, ErrPacket
	}
	if p.ACKCount != 0 {
		if len(body) < 4*p.ACKCount+len(p.ACKTarget) {
			return ControlPacket{}, ErrPacket
		}
		for i := range p.ACKs[:p.ACKCount] {
			p.ACKs[i] = binary.BigEndian.Uint32(body[:4])
			body = body[4:]
		}
		copy(p.ACKTarget[:], body)
		body = body[len(p.ACKTarget):]
	}

	if header.Opcode == ACK {
		if len(body) != 0 || p.ACKCount == 0 {
			return ControlPacket{}, ErrPacket
		}
		return p, nil
	}
	if len(body) < 4 {
		return ControlPacket{}, ErrPacket
	}
	p.ID = binary.BigEndian.Uint32(body[:4])
	p.Payload = body[4:]
	return p, nil
}
