package control

import (
	"sync"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/wire"
)

// The protected outer counter and its replay window belong to the link,
// independently of the reliable IDs in each TLS generation.
type frameProtection struct {
	codec codec
	mu    sync.Mutex
	wrap  replayWindow
}

func (p *frameProtection) seal(packet wire.ControlPacket) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.codec.seal(packet)
}

func (p *frameProtection) open(raw []byte) (wire.ControlPacket, uint32, uint32, error) {
	return p.codec.open(raw)
}

func (p *frameProtection) accept(counter, timestamp uint32) bool {
	if p.codec.mode == Plain {
		return true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.wrap.accept(counter, timestamp, time.Now())
}

func (p *frameProtection) mayAccept(counter, timestamp uint32) bool {
	if p.codec.mode == Plain {
		return true
	}
	p.mu.Lock()
	window := p.wrap
	p.mu.Unlock()
	return window.accept(counter, timestamp, time.Now())
}
