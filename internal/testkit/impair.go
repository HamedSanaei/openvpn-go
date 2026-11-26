package testkit

import (
	"context"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const RelayCapacity = 32

// Relay is an isolated single-client loopback UDP simulator. Its decisions
// are reproducible for the same seed, direction and arrival order.
type Relay struct {
	front, upstream *net.UDPConn
	client          atomic.Pointer[net.UDPAddr]
	cancel          context.CancelFunc
	workers         sync.WaitGroup
	once            sync.Once
	pipes           [2]relayPipe
}

type RelayStats struct {
	Received, Delivered, Lost, Duplicated, Overflow uint64
	Reordered                                       uint64
	PeakQueued                                      int32
}

type relayPipe struct {
	received, delivered, lost, duplicated, overflow atomic.Uint64
	reordered                                       atomic.Uint64
	depth, peak                                     atomic.Int32
}

type datagram struct {
	data  []byte
	due   time.Time
	order uint64
}

func NewRelay(remote *net.UDPAddr, seed uint64) (*Relay, error) {
	front, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	upstream, err := net.DialUDP("udp4", nil, remote)
	if err != nil {
		front.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &Relay{front: front, upstream: upstream, cancel: cancel}
	r.launch(ctx, 0, seed, func(b []byte) (int, error) {
		n, peer, err := front.ReadFromUDP(b)
		if err == nil && !r.client.CompareAndSwap(nil, peer) {
			if r.client.Load().AddrPort() != peer.AddrPort() {
				return 0, nil
			}
		}
		return n, err
	}, upstream.Write)
	r.launch(ctx, 1, seed, upstream.Read, func(b []byte) (int, error) {
		if peer := r.client.Load(); peer != nil {
			return front.WriteToUDP(b, peer)
		}
		return 0, nil
	})
	return r, nil
}

func (r *Relay) Address() *net.UDPAddr { return r.front.LocalAddr().(*net.UDPAddr) }

func (r *Relay) Close() {
	r.once.Do(func() {
		r.cancel()
		r.front.Close()
		r.upstream.Close()
		r.workers.Wait()
	})
}

func (r *Relay) Stats() [2]RelayStats {
	var stats [2]RelayStats
	for i := range stats {
		p := &r.pipes[i]
		stats[i] = RelayStats{p.received.Load(), p.delivered.Load(), p.lost.Load(),
			p.duplicated.Load(), p.overflow.Load(), p.reordered.Load(), p.peak.Load()}
	}
	return stats
}

func (r *Relay) launch(ctx context.Context, dir int, seed uint64, read, write func([]byte) (int, error)) {
	p := &r.pipes[dir]
	input := make(chan datagram, RelayCapacity)
	r.workers.Go(func() {
		random := rand.New(rand.NewPCG(seed, uint64(dir+1)))
		var buf [65535]byte
		for ctx.Err() == nil {
			n, err := read(buf[:])
			if err != nil {
				return
			}
			if n == 0 {
				continue
			}
			order := p.received.Add(1)
			delays := [2]int{random.IntN(7), random.IntN(7)}
			if random.IntN(31) == 0 {
				p.lost.Add(1)
				continue
			}
			copies := 1
			if random.IntN(9) == 0 {
				copies++
				p.duplicated.Add(1)
			}
			data := append([]byte(nil), buf[:n]...)
			now := time.Now()
			for _, delay := range delays[:copies] {
				depth := p.depth.Add(1)
				if depth > RelayCapacity {
					p.overflow.Add(1)
					p.depth.Add(-1)
					continue
				}
				if depth > p.peak.Load() {
					p.peak.Store(depth)
				}
				input <- datagram{data: data, due: now.Add(time.Duration(delay) * time.Millisecond), order: order}
			}
		}
	})
	r.workers.Go(func() {
		queue := make([]datagram, 0, RelayCapacity)
		var deliveredOrder uint64
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case d := <-input:
				queue = append(queue, d)
			case now := <-tick.C:
				pending := queue[:0]
				for _, d := range queue {
					if now.Before(d.due) {
						pending = append(pending, d)
						continue
					}
					if n, err := write(d.data); err == nil && n == len(d.data) {
						p.delivered.Add(1)
						if d.order < deliveredOrder {
							p.reordered.Add(1)
						}
						deliveredOrder = max(deliveredOrder, d.order)
					}
					p.depth.Add(-1)
				}
				clear(queue[len(pending):])
				queue = pending
			}
		}
	})
}
