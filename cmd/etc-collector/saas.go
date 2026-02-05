package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	enrollToken string
	saasURL     string
)

// enrollCmd handles enrollment
var enrollCmd = &cobra.Command{
	Use:   "enroll [token]",
	Short: "Enroll this collector with the SaaS platform",
	Long: `Enroll this collector instance with the ETC Security SaaS platform.

You need an enrollment token from your organization's dashboard.
The token can be provided as an argument or via ETCSEC_ENROLL_TOKEN environment variable.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runEnroll,
}

// daemonCmd handles daemon mode
var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Run in daemon mode (SaaS)",
	Long: `Run the collector in daemon mode for SaaS integration.

The collector must be enrolled first using the 'enroll' command.
In daemon mode, the collector will periodically run audits and
report results to the SaaS platform.`,
	RunE: runDaemon,
}

// statusCmd shows enrollment status
var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show enrollment status",
	RunE:  runStatus,
}

// unenrollCmd removes enrollment
var unenrollCmd = &cobra.Command{
	Use:   "unenroll",
	Short: "Remove enrollment from SaaS platform",
	RunE:  runUnenroll,
}

func init() {
	rootCmd.AddCommand(enrollCmd)
	rootCmd.AddCommand(daemonCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(unenrollCmd)

	// Enroll flags
	enrollCmd.Flags().StringVar(&saasURL, "saas-url", "https://api.etcsec.com", "SaaS API URL")
	viper.BindPFlag("saas.url", enrollCmd.Flags().Lookup("saas-url"))
	viper.BindEnv("saas.url", "ETCSEC_SAAS_URL")

	// Token from env
	viper.BindEnv("enroll.token", "ETCSEC_ENROLL_TOKEN")
}

func runEnroll(cmd *cobra.Command, args []string) error {
	// Get token from args or env
	token := ""
	if len(args) > 0 {
		token = args[0]
	} else {
		token = viper.GetString("enroll.token")
	}

	if token == "" {
		return fmt.Errorf("enrollment token required (as argument or ETCSEC_ENROLL_TOKEN)")
	}

	log.Info("Starting enrollment",
		"saas_url", viper.GetString("saas.url"),
	)

	// TODO: Implement enrollment
	// 1. Call SaaS API with token
	// 2. Receive credentials (API token, LDAP config)
	// 3. Store encrypted credentials locally

	fmt.Println("Enrollment not yet implemented")
	return nil
}

func runDaemon(cmd *cobra.Command, args []string) error {
	log.Info("Starting daemon mode")

	// TODO: Implement daemon
	// 1. Load credentials from store
	// 2. Initialize LDAP provider
	// 3. Start periodic audit loop
	// 4. Report results to SaaS

	fmt.Println("Daemon mode not yet implemented")
	return nil
}

func runStatus(cmd *cobra.Command, args []string) error {
	// TODO: Check credential store
	// For now, just check if credentials file exists

	dataDir := getDataDir()
	credFile := dataDir + "/credentials.enc"

	if _, err := os.Stat(credFile); os.IsNotExist(err) {
		fmt.Println("Status: Not enrolled")
		return nil
	}

	fmt.Println("Status: Enrolled")
	fmt.Printf("Credentials file: %s\n", credFile)

	// TODO: Load and display collector ID, LDAP URL, etc.

	return nil
}

func runUnenroll(cmd *cobra.Command, args []string) error {
	log.Info("Starting unenrollment")

	// TODO: Implement unenroll
	// 1. Load credentials
	// 2. Call SaaS API to unenroll
	// 3. Delete local credentials

	fmt.Println("Unenrollment not yet implemented")
	return nil
}

// getDataDir returns the data directory path
func getDataDir() string {
	// Check environment variable first
	if dir := os.Getenv("ETCSEC_DATA_DIR"); dir != "" {
		return dir
	}

	// Default based on OS
	switch {
	case isWindows():
		// Use executable directory on Windows
		exe, _ := os.Executable()
		return filepath.Dir(exe) + "\\data"
	default:
		// Use current directory or /var/lib/etc-collector
		if _, err := os.Stat("/var/lib/etc-collector"); err == nil {
			return "/var/lib/etc-collector"
		}
		return "./data"
	}
}

func isWindows() bool {
	return os.PathSeparator == '\\'
}
