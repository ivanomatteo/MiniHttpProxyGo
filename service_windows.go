//go:build windows
package main

import (
	"golang.org/x/sys/windows/svc"
)

func runService(cfgPath string) error {
	isSvc, err := svc.IsWindowsService()
	if err != nil {
		return err
	}

	if isSvc {
		return svc.Run("mini-proxy", &proxyService{cfgPath: cfgPath})
	}

	// Run as normal console app
	stopChan := make(chan struct{})
	return runProxy(cfgPath, stopChan)
}

type proxyService struct {
	cfgPath string
}

func (m *proxyService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	stopChan := make(chan struct{})
	errChan := make(chan error, 1)

	go func() {
		errChan <- runProxy(m.cfgPath, stopChan)
	}()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

loop:
	for {
		select {
		case err := <-errChan:
			if err != nil {
				return false, 1
			}
			return false, 0
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				close(stopChan)
				changes <- svc.Status{State: svc.StopPending}
				break loop
			default:
				// ignore
			}
		}
	}

	return
}
