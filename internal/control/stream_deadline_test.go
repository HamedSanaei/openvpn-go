package control

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"testing/synctest"
	"time"
)

func TestWriteDeadlineWhileDrainOwnsGate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pipe, peer := net.Pipe()
		defer pipe.Close()
		defer peer.Close()
		s := &Stream{conn: pipe, writer: make(chan struct{}, 1), stopped: make(chan struct{}),
			drain: make(chan drainRequest), deadlineChanged: make(chan struct{})}
		writer, deadlines := s.Conn(), s.Conn()
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		drained := make(chan error, 1)
		go func() { drained <- s.Drain(ctx) }()
		synctest.Wait()
		if len(s.writer) != 1 {
			t.Fatal("Drain did not hold the writer gate")
		}
		write := func() <-chan error {
			done := make(chan error, 1)
			go func() {
				_, err := writer.Write([]byte{1})
				done <- err
			}()
			synctest.Wait()
			return done
		}
		first := write()
		start := time.Now()
		if err := deadlines.SetWriteDeadline(start.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if err := <-first; !errors.Is(err, os.ErrDeadlineExceeded) || time.Since(start) != time.Second {
			t.Fatalf("queued write returned %v after %v", err, time.Since(start))
		}
		if err := <-write(); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("past deadline returned %v", err)
		}
		if err := deadlines.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		second := write()
		if err := deadlines.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Second)
		select {
		case err := <-second:
			t.Fatalf("extended deadline returned early: %v", err)
		default:
		}
		if err := deadlines.SetDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Second)
		select {
		case err := <-second:
			t.Fatalf("cleared deadline returned early: %v", err)
		default:
		}
		cancel()
		if err := <-drained; !errors.Is(err, context.Canceled) {
			t.Fatalf("drain returned %v", err)
		}
		buf := make([]byte, 1)
		if n, err := peer.Read(buf); err != nil || n != 1 || buf[0] != 1 {
			t.Fatalf("released writer did not deliver its packet: n=%d err=%v", n, err)
		}
		if err := <-second; err != nil {
			t.Fatal(err)
		}
	})
}
