//go:build windows

package main

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "etc-collector"
const serviceDisplayName = "ETC Collector"
const serviceDescription = "Identity security audit collector for Active Directory"

var elog debug.Log

// windowsService implements svc.Handler
type windowsService struct{}

func (ws *windowsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	changes <- svc.Status{State: svc.StartPending}
	elog.Info(1, fmt.Sprintf("Starting %s service", serviceName))

	// Start the daemon
	// Note: In real implementation, daemon would be started here
	// daemon, err := startDaemon()
	// if err != nil {
	//     elog.Error(1, fmt.Sprintf("Failed to start daemon: %v", err))
	//     return
	// }

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	elog.Info(1, fmt.Sprintf("%s service is now running", serviceName))

loop:
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
				time.Sleep(100 * time.Millisecond)
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				elog.Info(1, fmt.Sprintf("Stopping %s service", serviceName))
				break loop
			default:
				elog.Error(1, fmt.Sprintf("Unexpected control request #%d", c))
			}
		}
	}

	changes <- svc.Status{State: svc.StopPending}

	// Stop the daemon
	// daemon.Stop()

	return
}

// runService runs as a Windows service
func runService(isDebug bool) error {
	var err error
	if isDebug {
		elog = debug.New(serviceName)
	} else {
		elog, err = eventlog.Open(serviceName)
		if err != nil {
			return fmt.Errorf("failed to open event log: %w", err)
		}
	}
	defer elog.Close()

	elog.Info(1, fmt.Sprintf("Starting %s service", serviceName))
	run := svc.Run
	if isDebug {
		run = debug.Run
	}

	err = run(serviceName, &windowsService{})
	if err != nil {
		elog.Error(1, fmt.Sprintf("%s service failed: %v", serviceName, err))
		return err
	}

	elog.Info(1, fmt.Sprintf("%s service stopped", serviceName))
	return nil
}

// installService installs the Windows service
func installService() error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists", serviceName)
	}

	s, err = m.CreateService(serviceName, exePath, mgr.Config{
		DisplayName: serviceDisplayName,
		Description: serviceDescription,
		StartType:   mgr.StartAutomatic,
	}, "--daemon")
	if err != nil {
		return fmt.Errorf("failed to create service: %w", err)
	}
	defer s.Close()

	// Set up event logging
	err = eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)
	if err != nil {
		s.Delete()
		return fmt.Errorf("failed to install event log: %w", err)
	}

	fmt.Printf("Service %s installed successfully\n", serviceName)
	return nil
}

// uninstallService removes the Windows service
func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", serviceName)
	}
	defer s.Close()

	err = s.Delete()
	if err != nil {
		return fmt.Errorf("failed to delete service: %w", err)
	}

	err = eventlog.Remove(serviceName)
	if err != nil {
		return fmt.Errorf("failed to remove event log: %w", err)
	}

	fmt.Printf("Service %s removed successfully\n", serviceName)
	return nil
}

// isWindowsService checks if running as a Windows service
func isWindowsService() bool {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return false
	}
	return isService
}
