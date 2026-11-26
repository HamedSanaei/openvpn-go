package failover

import (
	"testing"
	"time"
)

func TestBackoffCeilingAndEqualJitter(t *testing.T) {
	for _, edge := range []struct {
		name   string
		sample func(n time.Duration) time.Duration
	}{
		{"lower", func(time.Duration) time.Duration { return 0 }},
		{"upper", func(n time.Duration) time.Duration { return n - 1 }},
	} {
		t.Run(edge.name, func(t *testing.T) {
			b := NewBackoff(100*time.Millisecond, 750*time.Millisecond)
			for _, ceiling := range []time.Duration{100, 200, 400, 750, 750} {
				ceiling *= time.Millisecond
				want := ceiling/2 + edge.sample(ceiling-ceiling/2+1)
				if got := b.Next(edge.sample); got != want {
					t.Fatalf("delay = %v, want %v", got, want)
				}
			}
		})
	}
}
