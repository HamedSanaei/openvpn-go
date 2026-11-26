package testkit

import (
	"testing"
	"time"
)

func TestClockAdvanceAndStop(t *testing.T) {
	start := time.Unix(120, 0)
	clock := NewClock(start)
	first := clock.NewTimer(time.Second)
	stopped := clock.NewTimer(2 * time.Second)
	last := clock.NewTimer(3 * time.Second)
	immediate := clock.NewTimer(0)
	if at := <-immediate.C(); !at.Equal(start) {
		t.Fatalf("immediate timer = %v; want %v", at, start)
	}
	if !stopped.Stop() || stopped.Stop() {
		t.Fatal("stopped timer must report one pending stop")
	}

	clock.Advance(time.Second)
	if at := <-first.C(); !at.Equal(start.Add(time.Second)) {
		t.Fatalf("first timer = %v", at)
	}
	if first.Stop() {
		t.Fatal("fired timer was still pending")
	}
	select {
	case <-last.C():
		t.Fatal("last timer fired too early")
	default:
	}
	clock.Advance(10 * time.Second)
	if at := <-last.C(); !at.Equal(start.Add(3 * time.Second)) {
		t.Fatalf("last timer time = %v", at)
	}
	if now := clock.Now(); !now.Equal(start.Add(11 * time.Second)) {
		t.Fatalf("Now = %v", now)
	}
	select {
	case <-stopped.C():
		t.Fatal("stopped timer fired")
	default:
	}
}
