//go:build !windows
package main

import (
	"os"
	"os/signal"
	"syscall"
)

func runService(cfgPath string) error {
	stopChan := make(chan struct{})
	
	// Handle SIGINT and SIGTERM for graceful shutdown on Linux/Unix
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigs
		close(stopChan)
	}()

	return runProxy(cfgPath, stopChan)
}
