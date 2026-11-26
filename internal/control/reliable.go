package control

import (
	"context"
	"encoding/binary"
	"math"
	"slices"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/wire"
	"github.com/hamedsanaei/openvpn-go/transport"
)

const (
	windowSize       = 12
	maxControlHeader = wire.PrefixSize + 1 + 4*wire.MaxACKs + 8 + 4
	ackDelay         = 10 * time.Millisecond
	initialRetry     = 2 * time.Second
	maxRetryInterval = 16 * time.Second
	maxRetransmits   = 6
)

type flight struct {
	id      uint32
	opcode  wire.Opcode
	payload []byte
	sends   int
	due     time.Time
}

type driver struct {
	packets transport.PacketConn
	codec   *frameProtection
	udp     bool

	local wire.SessionID
	peer  wire.SessionID
	bound bool
	keyID uint8

	sendID uint32
	recvID uint32
	tx     []flight
	rx     map[uint32][]byte

	acks    []uint32
	ackTime time.Time
}

func newDriver(packets transport.PacketConn, codec *frameProtection, udp bool) *driver {
	return &driver{
		packets: packets,
		codec:   codec,
		udp:     udp,
		tx:      make([]flight, 0, windowSize),
		rx:      make(map[uint32][]byte, windowSize),
		acks:    make([]uint32, 0, wire.MaxACKs),
	}
}

func (d *driver) loop(ctx context.Context, incoming, outgoing <-chan []byte, delivery chan<- []byte, drain <-chan chan struct{}, ready func()) error {
	reset := wire.ClientReset
	if d.keyID != 0 {
		reset = wire.SoftReset
	} else if d.codec.codec.mode == TLSCryptV2 {
		reset = wire.ClientV3
	}
	if err := d.enqueue(ctx, reset, nil); err != nil {
		return err
	}

	timer := time.NewTimer(0)
	defer timer.Stop()
	var flushing chan struct{}
	for {
		var drainRequest <-chan chan struct{}
		if flushing == nil {
			drainRequest = drain
		} else {
			if !d.ackTime.IsZero() {
				if err := d.send(ctx, wire.ControlPacket{Header: wire.Header{Opcode: wire.ACK}}); err != nil {
					return err
				}
			}
			if len(d.tx) == 0 {
				close(flushing)
				flushing = nil
				drainRequest = drain
			}
		}
		var write <-chan []byte
		if d.bound && d.canSend() {
			write = outgoing
		}
		var deliver chan<- []byte
		payload, hasPayload := d.rx[d.recvID]
		if hasPayload {
			if len(payload) == 0 {
				d.received()
				continue
			}
			deliver = delivery
		}
		timer.Stop()
		var wake <-chan time.Time
		if next := d.wakeup(); !next.IsZero() {
			timer.Reset(time.Until(next))
			wake = timer.C
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case flushing = <-drainRequest:
		case raw := <-incoming:
			wasBound := d.bound
			if err := d.receive(ctx, raw); err != nil {
				return err
			}
			if !wasBound && d.bound {
				ready()
			}
		case payload := <-write:
			if err := d.enqueue(ctx, wire.Control, payload); err != nil {
				return err
			}
		case deliver <- payload:
			d.received()
		case <-wake:
			if err := d.tick(ctx, time.Now()); err != nil {
				return err
			}
		}
	}
}

func (d *driver) received() {
	delete(d.rx, d.recvID)
	d.recvID++
}

func (d *driver) canSend() bool {
	return len(d.tx) == 0 || d.sendID-d.tx[0].id < windowSize
}

func (d *driver) enqueue(ctx context.Context, op wire.Opcode, payload []byte) error {
	if !d.canSend() || d.sendID == math.MaxUint32 {
		return ErrReliable
	}
	d.tx = append(d.tx, flight{id: d.sendID, opcode: op, payload: payload})
	d.sendID++
	return d.transmit(ctx, &d.tx[len(d.tx)-1])
}

func (d *driver) transmit(ctx context.Context, item *flight) error {
	if item.sends > maxRetransmits {
		return ErrReliable
	}
	p := wire.ControlPacket{Header: wire.Header{Opcode: item.opcode}, ID: item.id, Payload: item.payload}
	if p.Opcode == wire.WrappedKey {
		// A stateless server must see the server reset ACK each time it
		// receives the wrapped-key continuation, even after packet loss.
		p.ACKs[0] = 0
		p.ACKCount = 1
	}
	if err := d.send(ctx, p); err != nil {
		return err
	}
	item.due = time.Now().Add(min(initialRetry<<item.sends, maxRetryInterval))
	item.sends++
	return nil
}

func (d *driver) send(ctx context.Context, p wire.ControlPacket) error {
	p.KeyID = d.keyID
	p.Sender = d.local
	p.ACKTarget = d.peer
	for _, id := range d.acks {
		if p.ACKCount == len(p.ACKs) {
			break
		}
		if !slices.Contains(p.ACKs[:p.ACKCount], id) {
			p.ACKs[p.ACKCount] = id
			p.ACKCount++
		}
	}
	packet, err := d.codec.seal(p)
	if err != nil {
		return ErrReliable
	}
	writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := d.packets.WritePacket(writeCtx, packet); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrTransport
	}
	d.ackTime = time.Time{}
	return nil
}

func (d *driver) receive(ctx context.Context, raw []byte) error {
	header, err := wire.ParseHeader(raw)
	reset := wire.ServerReset
	if d.keyID != 0 {
		reset = wire.SoftReset
	}
	if err != nil || header.KeyID != d.keyID ||
		(header.Opcode != reset && header.Opcode != wire.Control && header.Opcode != wire.ACK) {
		return nil
	}
	p, counter, timestamp, err := d.codec.open(raw)
	if err != nil || p.Sender == (wire.SessionID{}) ||
		(p.ACKCount != 0 && p.ACKTarget != d.local) {
		return nil
	}
	if !d.bound {
		if p.Opcode != reset || p.ID != 0 ||
			(d.keyID == 0 && !slices.Contains(p.ACKs[:p.ACKCount], uint32(0))) ||
			(d.keyID != 0 && (p.Sender != d.peer || len(p.Payload) != 0)) {
			return nil
		}
		resend := false
		if d.keyID == 0 && d.codec.codec.mode == TLSCryptV2 {
			var ok bool
			resend, ok = resendWrappedKey(p.Payload)
			if !ok {
				return nil
			}
		}
		if !d.codec.accept(counter, timestamp) {
			return nil
		}
		d.peer, d.bound, d.recvID = p.Sender, true, 1
		d.acknowledge(p.ACKs[:p.ACKCount])
		if err := d.queueACK(ctx, 0); err != nil {
			return err
		}
		if resend {
			return d.enqueue(ctx, wire.WrappedKey, nil)
		}
		return d.send(ctx, wire.ControlPacket{Header: wire.Header{Opcode: wire.ACK}})
	}

	if p.Sender != d.peer || (p.Opcode == reset && p.ID != 0) {
		return nil
	}
	if !d.codec.accept(counter, timestamp) {
		return nil
	}
	d.acknowledge(p.ACKs[:p.ACKCount])
	if p.Opcode == wire.ACK {
		return nil
	}
	if p.ID < d.recvID {
		if d.recvID-p.ID <= windowSize {
			return d.queueACK(ctx, p.ID)
		}
		return nil
	}
	if p.ID == math.MaxUint32 || p.ID-d.recvID >= windowSize {
		return nil
	}
	if _, found := d.rx[p.ID]; !found {
		d.rx[p.ID] = p.Payload
	}
	return d.queueACK(ctx, p.ID)
}

func (d *driver) acknowledge(ids []uint32) {
	d.tx = slices.DeleteFunc(d.tx, func(item flight) bool {
		return slices.Contains(ids, item.id)
	})
}

func (d *driver) queueACK(ctx context.Context, id uint32) error {
	if index := slices.Index(d.acks, id); index >= 0 {
		d.acks = slices.Delete(d.acks, index, index+1)
	} else if len(d.acks) == wire.MaxACKs {
		if !d.ackTime.IsZero() {
			if err := d.send(ctx, wire.ControlPacket{Header: wire.Header{Opcode: wire.ACK}}); err != nil {
				return err
			}
		}
		d.acks = d.acks[:wire.MaxACKs-1]
	}
	d.acks = slices.Insert(d.acks, 0, id)
	if d.ackTime.IsZero() {
		d.ackTime = time.Now().Add(ackDelay)
	}
	return nil
}

func (d *driver) wakeup() time.Time {
	next := d.ackTime
	if d.udp {
		for _, item := range d.tx {
			if next.IsZero() || item.due.Before(next) {
				next = item.due
			}
		}
	}
	return next
}

func (d *driver) tick(ctx context.Context, now time.Time) error {
	if d.udp {
		for i := range d.tx {
			if at := d.tx[i].due; !at.After(now) {
				if err := d.transmit(ctx, &d.tx[i]); err != nil {
					return err
				}
			}
		}
	}
	if !d.ackTime.IsZero() && !d.ackTime.After(now) {
		return d.send(ctx, wire.ControlPacket{Header: wire.Header{Opcode: wire.ACK}})
	}
	return nil
}

func resendWrappedKey(payload []byte) (bool, bool) {
	var found, resend bool
	for len(payload) != 0 {
		if len(payload) < 4 {
			return false, false
		}
		kind := binary.BigEndian.Uint16(payload[:2])
		size := int(binary.BigEndian.Uint16(payload[2:4]))
		payload = payload[4:]
		if size > len(payload) {
			return false, false
		}
		if kind == 1 {
			if size != 2 || found {
				return false, false
			}
			found = true
			resend = binary.BigEndian.Uint16(payload[:2])&1 != 0
		}
		payload = payload[size:]
	}
	return resend, true
}
