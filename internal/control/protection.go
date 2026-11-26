package control

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"hash"
	"math"

	"github.com/hamedsanaei/openvpn-go/internal/wire"
)

type Mode uint8

const (
	Plain Mode = iota
	TLSAuth
	TLSCrypt
	TLSCryptV2
)

type Direction uint8

const (
	Bidirectional Direction = iota
	Direction0
	Direction1
)

const (
	staticSize     = 256
	outerIDSize    = 8
	maxWrappedSize = 1024
	earlyCounter   = 0x0f000000
)

var (
	ErrProtection = errors.New("invalid OpenVPN control protection configuration")
	errCounter    = errors.New("OpenVPN control replay counter exhausted")
)

type Protection struct {
	mode    Mode
	digest  func() hash.Hash
	tx      key
	rx      key
	wrapped []byte
}

type key struct {
	block cipher.Block
	mac   []byte
}

// NewProtection prepares control keys and owns its copy of the parsed material.
func NewProtection(mode Mode, direction Direction, digest string, encoded []byte) (Protection, error) {
	if len(encoded) > 16*1024 {
		return Protection{}, ErrProtection
	}
	if mode == Plain {
		if len(encoded) != 0 || direction != Bidirectional || digest != "" {
			return Protection{}, ErrProtection
		}
		return Protection{}, nil
	}

	p := Protection{mode: mode}
	switch mode {
	case TLSAuth:
		switch digest {
		case "", "SHA1":
			p.digest = sha1.New
		case "SHA256":
			p.digest = sha256.New
		case "SHA384":
			p.digest = sha512.New384
		case "SHA512":
			p.digest = sha512.New
		default:
			return Protection{}, ErrProtection
		}
		if direction > Direction1 {
			return Protection{}, ErrProtection
		}
	case TLSCrypt, TLSCryptV2:
		if direction != Bidirectional || digest != "" {
			return Protection{}, ErrProtection
		}
		p.digest = sha256.New
		direction = Direction1
	default:
		return Protection{}, ErrProtection
	}

	var raw []byte
	if mode == TLSCryptV2 {
		block, trailing := pem.Decode(bytes.TrimSpace(encoded))
		if block == nil || block.Type != "OpenVPN tls-crypt-v2 client key" ||
			len(block.Headers) != 0 || len(bytes.TrimSpace(trailing)) != 0 {
			return Protection{}, ErrProtection
		}
		raw = block.Bytes
		defer clear(raw)
		size := len(raw) - staticSize
		if size < sha256.Size+staticSize+2 || size > maxWrappedSize ||
			int(binary.BigEndian.Uint16(raw[len(raw)-2:])) != size {
			return Protection{}, ErrProtection
		}
		p.wrapped = bytes.Clone(raw[staticSize:])
	} else {
		var err error
		raw, err = parseStaticKey(encoded)
		if err != nil {
			return Protection{}, err
		}
		defer clear(raw)
	}

	var tx, rx int
	switch direction {
	case Direction0:
		rx = 128
	case Direction1:
		tx = 128
	}
	p.tx = p.newKey(raw[tx : tx+128])
	p.rx = p.newKey(raw[rx : rx+128])
	return p, nil
}

func parseStaticKey(encoded []byte) ([]byte, error) {
	var hexBytes [staticSize * 2]byte
	defer clear(hexBytes[:])
	var started bool
	var n int
	for len(encoded) != 0 {
		line, rest, _ := bytes.Cut(encoded, []byte{'\n'})
		encoded = rest
		line = bytes.TrimSpace(line)
		if !started {
			started = bytes.Equal(line, []byte("-----BEGIN OpenVPN Static key V1-----"))
			continue
		}
		if bytes.Equal(line, []byte("-----END OpenVPN Static key V1-----")) {
			if n != len(hexBytes) {
				return nil, ErrProtection
			}
			raw := make([]byte, staticSize)
			if _, err := hex.Decode(raw, hexBytes[:]); err != nil {
				clear(raw)
				return nil, ErrProtection
			}
			return raw, nil
		}
		if len(line) > len(hexBytes)-n {
			return nil, ErrProtection
		}
		n += copy(hexBytes[n:], line)
	}
	return nil, ErrProtection
}

func (p Protection) newKey(raw []byte) key {
	k := key{mac: bytes.Clone(raw[64 : 64+p.digest().Size()])}
	if p.mode != TLSAuth {
		k.block, _ = aes.NewCipher(raw[:32])
	}
	return k
}

type codec struct {
	Protection
	counter   uint32
	timestamp uint32
}

func newCodec(p Protection, timestamp uint32) codec {
	c := codec{Protection: p, timestamp: timestamp}
	if p.mode == TLSCryptV2 {
		c.counter = earlyCounter
	}
	return c
}

func (c *codec) overhead() int {
	if c.mode == Plain {
		return 0
	}
	return outerIDSize + c.digest().Size()
}

func (c *codec) seal(packet wire.ControlPacket) ([]byte, error) {
	prefix, err := packet.AppendPrefix(nil)
	if err != nil {
		return nil, err
	}
	if c.mode == Plain {
		return packet.AppendBody(prefix)
	}
	body, err := packet.AppendBody(nil)
	if err != nil {
		return nil, err
	}
	defer clear(body)
	if c.counter == math.MaxUint32 {
		return nil, errCounter
	}
	c.counter++
	var outer [outerIDSize]byte
	binary.BigEndian.PutUint32(outer[:4], c.counter)
	binary.BigEndian.PutUint32(outer[4:], c.timestamp)

	if c.mode == TLSAuth {
		tag := c.tag(c.tx, outer[:], prefix, body)
		packet := append(prefix, tag...)
		packet = append(packet, outer[:]...)
		return append(packet, body...), nil
	}

	tag := c.tag(c.tx, prefix, outer[:], body)
	out := append(prefix, outer[:]...)
	out = append(out, tag...)
	cipher.NewCTR(c.tx.block, tag[:aes.BlockSize]).XORKeyStream(body, body)
	out = append(out, body...)
	if packet.Opcode == wire.ClientV3 || packet.Opcode == wire.WrappedKey {
		out = append(out, c.wrapped...)
	}
	return out, nil
}

func (c *codec) open(packet []byte) (wire.ControlPacket, uint32, uint32, error) {
	if len(packet) <= wire.PrefixSize+c.overhead() {
		return wire.ControlPacket{}, 0, 0, wire.ErrPacket
	}
	prefix, rest := packet[:wire.PrefixSize], packet[wire.PrefixSize:]
	if c.mode == Plain {
		p, err := wire.ParseControl(prefix, rest)
		return p, 0, 0, err
	}
	tagSize := c.digest().Size()
	var outer, tag, body, want []byte
	if c.mode == TLSAuth {
		tag, outer, body = rest[:tagSize], rest[tagSize:tagSize+outerIDSize], rest[tagSize+outerIDSize:]
		want = c.tag(c.rx, outer, prefix, body)
	} else {
		outer, tag = rest[:outerIDSize], rest[outerIDSize:outerIDSize+tagSize]
		body = make([]byte, len(rest)-outerIDSize-tagSize)
		cipher.NewCTR(c.rx.block, tag[:aes.BlockSize]).XORKeyStream(body, rest[outerIDSize+tagSize:])
		want = c.tag(c.rx, prefix, outer, body)
	}
	if !hmac.Equal(tag, want) {
		return wire.ControlPacket{}, 0, 0, wire.ErrPacket
	}
	p, err := wire.ParseControl(prefix, body)
	return p, binary.BigEndian.Uint32(outer[:4]), binary.BigEndian.Uint32(outer[4:]), err
}

func (c *codec) tag(key key, parts ...[]byte) []byte {
	mac := hmac.New(c.digest, key.mac)
	for _, part := range parts {
		mac.Write(part)
	}
	return mac.Sum(nil)
}
