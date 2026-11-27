package session

import (
	"encoding/binary"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/data"
)

const (
	fragmentHeaderSize = 4
	maxFragments       = 32
	fragmentTTL        = 10 * time.Second
	maxPendingPackets  = 32
	uncompressedLZO    = 0xfa
)

// fragmenter handles the legacy UDP fragment records inside authenticated
// DATA_V2 packets. The only supported compression marker is uncompressed.
type fragmenter struct {
	chunkSize int
	sequence  uint8
	pending   map[fragmentKey]*fragmentSet
}

type fragmentKey struct {
	firstPacket uint32
	generation  byte
	sequence    byte
}

type fragmentSet struct {
	bytes    []byte
	expires  time.Time
	received uint32
	stride   int
	total    int
}

func (f *fragmenter) seal(ch *data.Channel, packet []byte) ([][]byte, error) {
	// Reuse one scratch buffer. Seal owns the resulting ciphertext.
	body := append(make([]byte, 0, len(packet)+1), uncompressedLZO)
	body = append(body, packet...)
	defer clear(body)
	frame := make([]byte, fragmentHeaderSize+min(len(body), f.chunkSize))
	defer clear(frame)
	if len(body) <= f.chunkSize {
		copy(frame[fragmentHeaderSize:], body)
		wrapped, err := ch.Seal(frame)
		return [][]byte{wrapped}, err
	}

	f.sequence++
	packets := make([][]byte, 0, (len(body)+f.chunkSize-1)/f.chunkSize)
	for offset, index := 0, 0; offset < len(body); offset, index = offset+f.chunkSize, index+1 {
		end := min(offset+f.chunkSize, len(body))
		header := uint32(1 | int(f.sequence)<<2 | index<<10)
		if end == len(body) {
			header = header&^3 | 2 | uint32(f.chunkSize/4)<<15
		}
		binary.BigEndian.PutUint32(frame, header)
		copy(frame[fragmentHeaderSize:], body[offset:end])
		wrapped, err := ch.Seal(frame[:fragmentHeaderSize+end-offset])
		if err != nil {
			return nil, err
		}
		packets = append(packets, wrapped)
	}
	return packets, nil
}

func (f *fragmenter) open(wrapped, plaintext []byte, mtu int, now time.Time) []byte {
	if len(plaintext) <= fragmentHeaderSize {
		clear(plaintext)
		return nil
	}
	header := binary.BigEndian.Uint32(plaintext)
	if header == 0 {
		return stripLZO(plaintext[fragmentHeaderSize:])
	}
	defer clear(plaintext)
	kind := header & 3
	index := int(header>>10) & 31
	if kind != 1 && kind != 2 || header>>29 != 0 {
		return nil
	}
	payload := plaintext[fragmentHeaderSize:]
	stride := len(payload)
	if kind == 1 {
		if header>>15 != 0 || index == maxFragments-1 {
			return nil
		}
	} else {
		stride = int(header>>15) * 4
		if index == 0 || len(payload) > stride {
			return nil
		}
	}
	start := stride * index
	if stride%4 != 0 || start+len(payload) > mtu+1 || kind == 1 && start+len(payload) >= mtu+1 {
		return nil
	}
	pid := binary.BigEndian.Uint32(wrapped[4:8])
	if pid <= uint32(index) {
		return nil
	}
	// All records of a datagram use one key generation and consecutive
	// packet IDs. Include both to isolate replay, sequence wrap and rekey.
	key := fragmentKey{pid - uint32(index), wrapped[0] & 7, byte(header >> 2)}
	set := f.pending[key]
	if set != nil && !now.Before(set.expires) {
		f.drop(key)
		set = nil
	}
	if set == nil {
		if len(f.pending) == maxPendingPackets {
			f.expire(now)
			if len(f.pending) == maxPendingPackets {
				return nil
			}
		}
		set = &fragmentSet{bytes: make([]byte, mtu+1), expires: now.Add(fragmentTTL), stride: stride}
		if f.pending == nil {
			f.pending = make(map[fragmentKey]*fragmentSet)
		}
		f.pending[key] = set
	}
	end := start + len(payload)
	bit := uint32(1) << index
	if stride != set.stride || set.received&bit != 0 ||
		(set.total != 0 && (end > set.total || kind == 2)) ||
		(kind == 2 && set.received>>index != 0) {
		f.drop(key)
		return nil
	}
	copy(set.bytes[start:end], payload)
	set.received |= bit
	if kind == 2 {
		set.total = end
	}
	if set.total == 0 || set.received != (uint32(1)<<((set.total-1)/stride+1))-1 {
		return nil
	}
	delete(f.pending, key)
	return stripLZO(set.bytes[:set.total])
}

func stripLZO(packet []byte) []byte {
	if len(packet) == 0 || packet[0] != uncompressedLZO {
		clear(packet)
		return nil
	}
	return packet[1:]
}

func (f *fragmenter) expire(now time.Time) {
	for key, set := range f.pending {
		if !now.Before(set.expires) {
			f.drop(key)
		}
	}
}

func (f *fragmenter) clear() {
	for key := range f.pending {
		f.drop(key)
	}
}

func (f *fragmenter) drop(key fragmentKey) {
	clear(f.pending[key].bytes)
	delete(f.pending, key)
}
