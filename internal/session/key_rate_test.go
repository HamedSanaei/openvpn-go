package session

import (
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/crypt"
	"github.com/hamedsanaei/openvpn-go/internal/data"
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
	if r.sendHeadroom != 450000 || r.receiveHeadroom != 225000 {
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
