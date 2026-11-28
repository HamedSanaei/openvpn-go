package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/crypt"
	"github.com/hamedsanaei/openvpn-go/internal/data"
	"github.com/hamedsanaei/openvpn-go/internal/tlscontrol"
)

func TestRateHeadroomTriggersEarlierWithoutChangingHardLimit(t *testing.T) {
	keys, err := crypt.ExportDataKeys(func(_ string, _ []byte, n int) ([]byte, error) { return make([]byte, n), nil }, crypt.AES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	keys.PacketLimit = 8192
	channel, err := data.NewChannel(0, false, keys)
	if err != nil {
		t.Fatal(err)
	}
	s := &Session{channel: channel, opts: Options{HandshakeLimit: 2 * time.Second}}
	now := time.Now()
	if s.sampleKeyRate(now) {
		t.Fatal("unused generation rekeyed")
	}
	var scratch []byte
	for range 6144 {
		scratch, err = channel.SealInto(scratch, []byte{1})
		if err != nil {
			t.Fatal(err)
		}
	}
	if channel.RekeyDue() || !s.sampleKeyRate(now.Add(250*time.Millisecond)) {
		t.Fatal("rate budget did not advance the rekey trigger")
	}
	for range 2048 {
		scratch, err = channel.SealInto(scratch, []byte{1})
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := channel.SealInto(scratch, []byte{1}); err != data.ErrKeyLimit {
		t.Fatalf("hard key limit changed: %v", err)
	}
	s.ctx, s.cancel = context.WithCancel(t.Context())
	defer s.cancel()
	s.writeGate, s.rotate = make(chan struct{}, 1), make(chan struct{}, 1)
	if err := s.write(t.Context(), []byte{1}, false); !errors.Is(err, data.ErrKeyLimit) ||
		!s.keyExhausted.Load() || !errors.Is(s.ctx.Err(), context.Canceled) {
		t.Fatalf("hard limit did not terminate the session: %v", err)
	}
}

func TestKeyConsumptionRateBudgetsDirectionsIndependently(t *testing.T) {
	const aesLimit = 1 << 24
	const exchangeBudget = 4 * time.Second
	at := time.Now()
	var r keyConsumptionRate
	r.observe(at, data.KeyUsage{Epoch: 1, Limit: aesLimit}, exchangeBudget)
	if r.sendHeadroom != 0 || r.receiveHeadroom != 0 {
		t.Fatal("idle keys requested dynamic headroom")
	}
	r.observe(at.Add(250*time.Millisecond), data.KeyUsage{Epoch: 1, Sent: 25000, Received: 12500, Limit: aesLimit}, exchangeBudget)
	if r.sendHeadroom != 450000 || r.receiveHeadroom != 3475000 {
		t.Fatalf("100k/50k PPS did not leave the shared admission and TLS budget: %+v", r)
	}
	r.observe(at.Add(500*time.Millisecond), data.KeyUsage{Epoch: 1, Sent: 50000, Received: 2000000, Limit: aesLimit}, exchangeBudget)
	if r.sendHeadroom != 450000 || r.receiveHeadroom != aesLimit/4 {
		t.Fatalf("burst allowance was not independently capped: %+v", r)
	}
	r.observe(at.Add(750*time.Millisecond), data.KeyUsage{Epoch: 2, Limit: aesLimit}, exchangeBudget)
	if r.sendHeadroom != 450000 || r.receiveHeadroom != aesLimit/4 {
		t.Fatalf("key promotion caused a false rate sample: %+v", r)
	}
	for tick := 4; tick <= 128; tick++ {
		r.observe(at.Add(time.Duration(tick)*250*time.Millisecond), data.KeyUsage{Epoch: 2, Limit: aesLimit}, exchangeBudget)
	}
	if r.sendHeadroom >= 1024 || r.receiveHeadroom >= 1024 {
		t.Fatalf("idle estimates kept unnecessary key headroom: %+v", r)
	}
}

func TestUsageRekeyPreservesBoundedReceiveHandoff(t *testing.T) {
	keys := func(fill byte, limit uint32) crypt.DataKeys {
		t.Helper()
		result, err := crypt.ExportDataKeys(func(_ string, _ []byte, n int) ([]byte, error) {
			raw := make([]byte, n)
			for i := range raw {
				raw[i] = fill
			}
			return raw, nil
		}, crypt.AES256GCM)
		if err != nil {
			t.Fatal(err)
		}
		result.PacketLimit = limit
		return result
	}
	old, next := keys(0, 2), keys(1, 8192)
	sender, err := data.NewChannel(0, true, old)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := data.NewChannel(0, true, old)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := receiver.Promote(1, next, now.Add(usageReceiveOverlap)); err != nil {
		t.Fatal(err)
	}
	s := &Session{channel: receiver, awaitingPeerKey: true,
		info: tlscontrol.Negotiation{PingTimeout: time.Second}}
	deliver := func() {
		t.Helper()
		encoded, err := sender.Seal([]byte(data.Keepalive))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.receive(encoded); err != nil {
			t.Fatal(err)
		}
	}
	deliver()
	if _, err := s.maintain(s.lastRecv.Add(time.Second)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ordinary idle outcome = %v", err)
	}
	deliver()
	if _, err := s.maintain(s.lastRecv.Add(time.Second)); !errors.Is(err, data.ErrKeyLimit) {
		t.Fatalf("authenticated retiring key limit lost its classification: %v", err)
	}
	if err := sender.Promote(1, next, now.Add(usageReceiveOverlap)); err != nil {
		t.Fatal(err)
	}
	deliver()
	if s.awaitingPeerKey || s.retiringReceiveExhausted {
		t.Fatal("authenticated replacement traffic did not finish the handoff")
	}
	receiver.Retire(s.lastRecv.Add(rekeyOverlap))
	if receiver.HasEpoch(1) {
		t.Fatal("extended receive overlap survived activation of the replacement")
	}
}
