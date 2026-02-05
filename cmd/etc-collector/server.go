package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	serverPort     int
	ldapURL        string
	ldapBindDN     string
	ldapBindPass   string
	ldapBaseDN     string
	ldapTLSVerify  bool
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the HTTP API server",
	Long: `Start the ETC Collector HTTP API server.

The server exposes a REST API for running audits and managing tokens.
API documentation is available at /docs when the server is running.`,
	Aliases: []string{"serve", "start"},
	RunE:    runServer,
}

func init() {
	rootCmd.AddCommand(serverCmd)

	// Server flags
	serverCmd.Flags().IntVarP(&serverPort, "port", "p", 8443, "API server port")
	serverCmd.Flags().StringVar(&ldapURL, "ldap-url", "", "LDAP server URL (e.g., ldaps://dc.example.com:636)")
	serverCmd.Flags().StringVar(&ldapBindDN, "ldap-bind-dn", "", "LDAP bind DN")
	serverCmd.Flags().StringVar(&ldapBindPass, "ldap-bind-password", "", "LDAP bind password")
	serverCmd.Flags().StringVar(&ldapBaseDN, "ldap-base-dn", "", "LDAP base DN for searches")
	serverCmd.Flags().BoolVar(&ldapTLSVerify, "ldap-tls-verify", true, "Verify LDAP TLS certificates")

	// Bind to viper
	viper.BindPFlag("api.port", serverCmd.Flags().Lookup("port"))
	viper.BindPFlag("ldap.url", serverCmd.Flags().Lookup("ldap-url"))
	viper.BindPFlag("ldap.bindDN", serverCmd.Flags().Lookup("ldap-bind-dn"))
	viper.BindPFlag("ldap.bindPassword", serverCmd.Flags().Lookup("ldap-bind-password"))
	viper.BindPFlag("ldap.baseDN", serverCmd.Flags().Lookup("ldap-base-dn"))
	viper.BindPFlag("ldap.tlsVerify", serverCmd.Flags().Lookup("ldap-tls-verify"))

	// Environment variable bindings
	viper.BindEnv("ldap.url", "LDAP_URL")
	viper.BindEnv("ldap.bindDN", "LDAP_BIND_DN")
	viper.BindEnv("ldap.bindPassword", "LDAP_BIND_PASSWORD")
	viper.BindEnv("ldap.baseDN", "LDAP_BASE_DN")
	viper.BindEnv("ldap.tlsVerify", "LDAP_TLS_VERIFY")
	viper.BindEnv("api.port", "PORT")
}

func runServer(cmd *cobra.Command, args []string) error {
	log.Info("Starting ETC Collector server",
		"version", Version,
		"port", viper.GetInt("api.port"),
	)

	// Validate LDAP configuration
	if viper.GetString("ldap.url") == "" {
		return fmt.Errorf("LDAP URL is required (--ldap-url or LDAP_URL)")
	}

	// Create context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Info("Received shutdown signal", "signal", sig.String())
		cancel()
	}()

	// TODO: Initialize providers
	// TODO: Initialize API server
	// TODO: Start server

	log.Info("Server configuration",
		"ldap_url", viper.GetString("ldap.url"),
		"ldap_base_dn", viper.GetString("ldap.baseDN"),
		"tls_verify", viper.GetBool("ldap.tlsVerify"),
	)

	// Placeholder - will be replaced with actual server
	fmt.Println("Server would start here (not yet implemented)")
	fmt.Printf("Press Ctrl+C to stop\n")

	<-ctx.Done()
	log.Info("Server stopped")

	return nil
}
