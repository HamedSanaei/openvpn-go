//go:build unix

package profile

import "syscall"

// Avoid blocking if a pathname is replaced by a FIFO before OpenFile.
const nonblockingOpen = syscall.O_NONBLOCK
