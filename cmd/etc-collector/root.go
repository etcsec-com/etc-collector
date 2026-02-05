package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/etcsec-com/etc-collector/internal/config"
	"github.com/etcsec-com/etc-collector/internal/logger"
)

var (
	cfgFile string
	verbose bool
	cfg     *config.Config
	log     *logger.Logger
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "etc-collector",
	Short: "Active Directory Security Auditing Tool",
	Long: `ETC Collector is a security auditing tool for Active Directory
and Azure AD / Entra ID environments.

It performs 196 security checks across 14 categories to identify
misconfigurations, vulnerabilities, and attack paths.`,
	Version: Version,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Skip init for version and help
		if cmd.Name() == "version" || cmd.Name() == "help" {
			return nil
		}

		// Initialize logger
		logLevel := "info"
		if verbose {
			logLevel = "debug"
		}
		var err error
		log, err = logger.New(logLevel, "console")
		if err != nil {
			return fmt.Errorf("failed to initialize logger: %w", err)
		}

		// Load configuration
		cfg, err = config.Load(cfgFile)
		if err != nil {
			log.Warn("Failed to load config file, using defaults", "error", err)
			cfg = config.Default()
		}

		return nil
	},
}

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./config.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "V", false, "enable verbose/debug output")

	// Bind to viper
	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		// Search for config in current directory
		viper.AddConfigPath(".")
		viper.AddConfigPath("/etc/etc-collector")
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}

	// Environment variables
	viper.SetEnvPrefix("ETCSEC")
	viper.AutomaticEnv()

	// Read config
	if err := viper.ReadInConfig(); err == nil {
		if verbose {
			fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
		}
	}
}
