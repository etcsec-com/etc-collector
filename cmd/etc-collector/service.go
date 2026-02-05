package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/spf13/cobra"
)

var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "Manage the ETC Collector service",
	Long: `Manage the ETC Collector as a system service.

On Windows, this installs/manages a Windows Service.
On Linux, this generates systemd unit files.

Examples:
  etc-collector service install --ldap-url ldaps://dc.example.com:636
  etc-collector service start
  etc-collector service stop
  etc-collector service status
  etc-collector service uninstall`,
}

var serviceInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install ETC Collector as a system service",
	Long: `Install ETC Collector as a system service.

On Windows, this creates a Windows Service that starts automatically.
On Linux, this creates a systemd unit file.

The service will use the configuration from:
- Command line flags (stored in service config)
- Environment variables
- Config file (./config.yaml or /etc/etc-collector/config.yaml)`,
	RunE: runServiceInstall,
}

var serviceUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstall the ETC Collector service",
	RunE:  runServiceUninstall,
}

var serviceStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the ETC Collector service",
	RunE:  runServiceStart,
}

var serviceStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the ETC Collector service",
	RunE:  runServiceStop,
}

var serviceStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the status of the ETC Collector service",
	RunE:  runServiceStatus,
}

var serviceRunCmd = &cobra.Command{
	Use:    "run",
	Short:  "Run the service (called by service manager)",
	Hidden: true, // Hidden as it's called by Windows Service Manager
	RunE:   runServiceRun,
}

// Service configuration flags
var (
	svcLdapURL      string
	svcLdapBindDN   string
	svcLdapBindPass string
	svcLdapBaseDN   string
	svcLdapTLSSkip  bool
	svcPort         int
)

func init() {
	rootCmd.AddCommand(serviceCmd)
	serviceCmd.AddCommand(serviceInstallCmd)
	serviceCmd.AddCommand(serviceUninstallCmd)
	serviceCmd.AddCommand(serviceStartCmd)
	serviceCmd.AddCommand(serviceStopCmd)
	serviceCmd.AddCommand(serviceStatusCmd)
	serviceCmd.AddCommand(serviceRunCmd)

	// Install command flags
	serviceInstallCmd.Flags().StringVar(&svcLdapURL, "ldap-url", "", "LDAP server URL (e.g., ldaps://dc.example.com:636)")
	serviceInstallCmd.Flags().StringVar(&svcLdapBindDN, "ldap-bind-dn", "", "LDAP bind DN")
	serviceInstallCmd.Flags().StringVar(&svcLdapBindPass, "ldap-bind-password", "", "LDAP bind password")
	serviceInstallCmd.Flags().StringVar(&svcLdapBaseDN, "ldap-base-dn", "", "LDAP base DN for searches")
	serviceInstallCmd.Flags().BoolVar(&svcLdapTLSSkip, "ldap-tls-skip-verify", false, "Skip LDAP TLS certificate verification")
	serviceInstallCmd.Flags().IntVar(&svcPort, "port", 8443, "API server port")
}

func runServiceInstall(cmd *cobra.Command, args []string) error {
	if runtime.GOOS == "windows" {
		return installWindowsService()
	}
	return installLinuxService()
}

func runServiceUninstall(cmd *cobra.Command, args []string) error {
	if runtime.GOOS == "windows" {
		return uninstallService()
	}
	return uninstallLinuxService()
}

func runServiceStart(cmd *cobra.Command, args []string) error {
	if runtime.GOOS == "windows" {
		return startWindowsService()
	}
	return startLinuxService()
}

func runServiceStop(cmd *cobra.Command, args []string) error {
	if runtime.GOOS == "windows" {
		return stopWindowsService()
	}
	return stopLinuxService()
}

func runServiceStatus(cmd *cobra.Command, args []string) error {
	if runtime.GOOS == "windows" {
		return statusWindowsService()
	}
	return statusLinuxService()
}

func runServiceRun(cmd *cobra.Command, args []string) error {
	// This is called by Windows Service Manager
	return runService(false)
}

// Linux service management using systemd
func installLinuxService() error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	unitContent := fmt.Sprintf(`[Unit]
Description=ETC Collector - Active Directory Security Audit
Documentation=https://github.com/etcsec-com/etc-collector
After=network.target

[Service]
Type=simple
ExecStart=%s server --port %d
Restart=always
RestartSec=5
User=root
WorkingDirectory=/opt/etc-collector

# Environment variables (uncomment and set)
#Environment="LDAP_URL=ldaps://dc.example.com:636"
#Environment="LDAP_BIND_DN=CN=service,CN=Users,DC=example,DC=com"
#Environment="LDAP_BIND_PASSWORD=password"
#Environment="LDAP_BASE_DN=DC=example,DC=com"

[Install]
WantedBy=multi-user.target
`, exePath, svcPort)

	unitPath := "/etc/systemd/system/etc-collector.service"
	if err := os.WriteFile(unitPath, []byte(unitContent), 0644); err != nil {
		return fmt.Errorf("failed to write systemd unit file: %w", err)
	}

	// Reload systemd
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}

	// Enable service
	if err := exec.Command("systemctl", "enable", "etc-collector").Run(); err != nil {
		return fmt.Errorf("failed to enable service: %w", err)
	}

	fmt.Println("Service installed successfully")
	fmt.Println("Edit /etc/systemd/system/etc-collector.service to set LDAP configuration")
	fmt.Println("Then run: etc-collector service start")
	return nil
}

func uninstallLinuxService() error {
	// Stop service first
	exec.Command("systemctl", "stop", "etc-collector").Run()
	exec.Command("systemctl", "disable", "etc-collector").Run()

	unitPath := "/etc/systemd/system/etc-collector.service"
	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove unit file: %w", err)
	}

	exec.Command("systemctl", "daemon-reload").Run()

	fmt.Println("Service uninstalled successfully")
	return nil
}

func startLinuxService() error {
	cmd := exec.Command("systemctl", "start", "etc-collector")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}
	fmt.Println("Service started")
	return nil
}

func stopLinuxService() error {
	cmd := exec.Command("systemctl", "stop", "etc-collector")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to stop service: %w", err)
	}
	fmt.Println("Service stopped")
	return nil
}

func statusLinuxService() error {
	cmd := exec.Command("systemctl", "status", "etc-collector")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run() // Ignore error, status returns non-zero if not running
	return nil
}
