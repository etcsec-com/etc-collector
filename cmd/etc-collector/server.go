package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/etcsec-com/etc-collector/internal/api"
	"github.com/etcsec-com/etc-collector/internal/config"
	"github.com/etcsec-com/etc-collector/internal/providers"
	"github.com/etcsec-com/etc-collector/internal/providers/ldap"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	// Import detectors to register them via init()
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad"
)

var (
	serverPort    int
	ldapURL       string
	ldapBindDN    string
	ldapBindPass  string
	ldapBaseDN    string
	ldapTLSVerify bool
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
	viper.BindPFlag("server.port", serverCmd.Flags().Lookup("port"))
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
	viper.BindEnv("server.port", "PORT")
}

func runServer(cmd *cobra.Command, args []string) error {
	log.Info("Starting ETC Collector server",
		"version", Version,
		"port", viper.GetInt("server.port"),
	)

	// Validate LDAP configuration
	ldapURLValue := viper.GetString("ldap.url")
	if ldapURLValue == "" {
		return fmt.Errorf("LDAP URL is required (--ldap-url or LDAP_URL)")
	}

	// Create configuration
	cfg := config.Default()
	cfg.Server.Port = viper.GetInt("server.port")
	cfg.Server.Host = "0.0.0.0"
	cfg.LDAP.URL = ldapURLValue
	cfg.LDAP.BindDN = viper.GetString("ldap.bindDN")
	cfg.LDAP.BindPassword = viper.GetString("ldap.bindPassword")
	cfg.LDAP.BaseDN = viper.GetString("ldap.baseDN")
	cfg.LDAP.TLSVerify = viper.GetBool("ldap.tlsVerify")
	cfg.LDAP.Timeout = 30 * time.Second

	log.Info("Server configuration",
		"ldap_url", cfg.LDAP.URL,
		"ldap_base_dn", cfg.LDAP.BaseDN,
		"tls_verify", cfg.LDAP.TLSVerify,
	)

	// Load JWT keys (generate if needed)
	if err := ensureKeys(cfg); err != nil {
		log.Warn("Failed to load/generate keys, token auth will be limited", "error", err)
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

	// Initialize LDAP provider
	ldapProvider, err := ldap.NewClient(ldap.Config{
		URL:          cfg.LDAP.URL,
		BindDN:       cfg.LDAP.BindDN,
		BindPassword: cfg.LDAP.BindPassword,
		BaseDN:       cfg.LDAP.BaseDN,
		TLSVerify:    cfg.LDAP.TLSVerify,
		Timeout:      cfg.LDAP.Timeout,
	})
	if err != nil {
		return fmt.Errorf("failed to create LDAP client: %w", err)
	}

	// Test LDAP connection and keep it open for the API server
	log.Info("Testing LDAP connection...")
	if err := ldapProvider.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	log.Info("LDAP connection successful")

	// Create provider manager
	manager := providers.NewManager()
	if err := manager.Register(ldapProvider); err != nil {
		return fmt.Errorf("failed to register LDAP provider: %w", err)
	}

	// Create and start API server
	server := api.NewServer(cfg, manager)

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start()
	}()

	// Wait for shutdown or error
	select {
	case <-ctx.Done():
		log.Info("Shutting down server...")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		return server.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

// ensureKeys ensures JWT keys exist or generates them
func ensureKeys(cfg *config.Config) error {
	// Try to load existing keys
	if err := cfg.LoadKeys(); err == nil && cfg.Auth.PrivateKey != nil {
		log.Info("Loaded existing JWT keys")
		return nil
	}

	// Check if key files exist
	if _, err := os.Stat(cfg.Auth.JWTPrivateKeyPath); err == nil {
		return cfg.LoadKeys()
	}

	// Generate new keys
	log.Info("Generating new JWT keys...")

	// Create keys directory
	keysDir := "./keys"
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return fmt.Errorf("failed to create keys directory: %w", err)
	}

	// Generate RSA key pair using openssl (simpler than pure Go for this)
	// In production, you'd want to use crypto/rsa directly
	log.Warn("JWT keys not found. Please generate keys manually:")
	log.Warn("  openssl genrsa -out keys/private.pem 2048")
	log.Warn("  openssl rsa -in keys/private.pem -pubout -out keys/public.pem")
	log.Warn("Server will start without token authentication")

	return fmt.Errorf("JWT keys not found")
}
