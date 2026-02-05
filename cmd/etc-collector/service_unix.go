//go:build !windows

package main

import "errors"

// runService is a no-op on non-Windows systems
func runService(isDebug bool) error {
	return errors.New("Windows service mode not supported on this platform")
}

// installService is a no-op on non-Windows systems
func installService() error {
	return errors.New("Windows service installation not supported on this platform")
}

// uninstallService is a no-op on non-Windows systems
func uninstallService() error {
	return errors.New("Windows service uninstallation not supported on this platform")
}

// isWindowsService always returns false on non-Windows systems
func isWindowsService() bool {
	return false
}
