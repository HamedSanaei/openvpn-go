//go:build linux && amd64

package transport

import (
	"fmt"
	"net"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// linuxMessage is the Linux amd64 mmsghdr layout used only by this benchmark.
type linuxMessage struct {
	header unix.Msghdr
	length uint32
}

func batchMessages(count, size int) []linuxMessage {
	batch := make([]linuxMessage, count)
	iov := make([]unix.Iovec, count)
	for i := range batch {
		payload := make([]byte, size)
		iov[i].Base = &payload[0]
		iov[i].SetLen(size)
		batch[i].header.Iov = &iov[i]
		batch[i].header.SetIovlen(1)
	}
	return batch
}

func batchCall(raw syscall.RawConn, messages []linuxMessage, send bool, attempts *uint64) (int, error) {
	call, poll := uintptr(unix.SYS_RECVMMSG), raw.Read
	if send {
		call, poll = unix.SYS_SENDMMSG, raw.Write
	}
	var count uintptr
	var failure syscall.Errno
	err := poll(func(fd uintptr) bool {
		for {
			(*attempts)++
			count, _, failure = unix.Syscall6(call, fd, uintptr(unsafe.Pointer(&messages[0])), uintptr(len(messages)), unix.MSG_DONTWAIT, 0, 0)
			runtime.KeepAlive(messages)
			if failure != unix.EINTR {
				return failure != unix.EAGAIN
			}
		}
	})
	if err != nil {
		return 0, err
	}
	if failure != 0 {
		return 0, failure
	}
	return int(count), nil
}

// BenchmarkLinuxUDPBatch compares socket calls for the same bounded batch
// and counts the calls directly, including attempts that encounter EAGAIN.
func BenchmarkLinuxUDPBatch(b *testing.B) {
	for _, size := range []int{64, 256, 1400} {
		for _, count := range []int{1, 8, 16, 32} {
			b.Run(fmt.Sprintf("%d/%d", size, count), func(b *testing.B) {
				listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					b.Fatal(err)
				}
				defer listener.Close()
				if err := listener.SetReadDeadline(time.Now().Add(20 * time.Second)); err != nil {
					b.Fatal(err)
				}
				sender, err := net.DialUDP("udp4", nil, listener.LocalAddr().(*net.UDPAddr))
				if err != nil {
					b.Fatal(err)
				}
				defer sender.Close()
				rx, err := listener.SyscallConn()
				if err != nil {
					b.Fatal(err)
				}
				tx, err := sender.SyscallConn()
				if err != nil {
					b.Fatal(err)
				}
				txMessages, rxMessages := batchMessages(count, size), batchMessages(count, size)
				var attempts uint64
				b.SetBytes(int64(size * count))
				b.ReportAllocs()
				for b.Loop() {
					walk := func(raw syscall.RawConn, messages []linuxMessage, send bool) {
						for len(messages) != 0 {
							n, err := batchCall(raw, messages, send, &attempts)
							if err != nil || n <= 0 || n > len(messages) {
								b.Fatalf("batch I/O: %d %v", n, err)
							}
							if !send {
								for _, packet := range messages[:n] {
									if packet.length != uint32(size) || packet.header.Flags&unix.MSG_TRUNC != 0 {
										b.Fatal("invalid datagram size in batch")
									}
								}
							}
							messages = messages[n:]
						}
					}
					walk(tx, txMessages, true)
					walk(rx, rxMessages, false)
				}
				b.ReportMetric(float64(attempts)/float64(b.N*count), "socket-calls/packet")
			})
		}
	}
}
