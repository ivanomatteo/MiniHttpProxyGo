//go:build windows

package main

import (
	"errors"
	"syscall"
)

// isPeerReset reports whether err means the peer reset or aborted the
// connection, as clients routinely do when they drop a tunnel.
func isPeerReset(err error) bool {
	return errors.Is(err, syscall.WSAECONNRESET) || errors.Is(err, syscall.WSAECONNABORTED) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) || errors.Is(err, syscall.EPIPE)
}
