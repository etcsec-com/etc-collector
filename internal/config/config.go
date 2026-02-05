// Package config handles application configuration
package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	Server ServerConfig `yaml:"server" mapstructure:"server"`
	API    APIConfig    `yaml:"api" mapstructure:"api"`
	LDAP   LDAPConfig   `yaml:"ldap" mapstructure:"ldap"`
	Azure  AzureConfig  `yaml:"azure" mapstructure:"azure"`
	Auth   AuthConfig   `yaml:"auth" mapstructure:"auth"`
	Log    LogConfig    `yaml:"log" mapstructure:"log"`
	SaaS   SaaSConfig   `yaml:"saas" mapstructure:"saas"`
}

// ServerConfig holds HTTP server configuration
type ServerConfig struct {
	Host        string `yaml:"host" mapstructure:"host"`
	Port        int    `yaml:"port" mapstructure:"port"`
	Environment string `yaml:"environment" mapstructure:"environment"`
	TLSEnabled  bool   `yaml:"tlsEnabled" mapstructure:"tlsEnabled"`
	TLSCertFile string `yaml:"tlsCertFile" mapstructure:"tlsCertFile"`
	TLSKeyFile  string `yaml:"tlsKeyFile" mapstructure:"tlsKeyFile"`
}

// APIConfig holds API server configuration
type APIConfig struct {
	Port       int         `yaml:"port" mapstructure:"port"`
	RateLimit  int         `yaml:"rateLimit" mapstructure:"rateLimit"`
	TLS        TLSConfig   `yaml:"tls" mapstructure:"tls"`
}

// TLSConfig holds TLS configuration
type TLSConfig struct {
	Enabled  bool   `yaml:"enabled" mapstructure:"enabled"`
	CertFile string `yaml:"certFile" mapstructure:"certFile"`
	KeyFile  string `yaml:"keyFile" mapstructure:"keyFile"`
}

// LDAPConfig holds LDAP provider configuration
type LDAPConfig struct {
	URL          string        `yaml:"url" mapstructure:"url"`
	BindDN       string        `yaml:"bindDN" mapstructure:"bindDN"`
	BindPassword string        `yaml:"bindPassword" mapstructure:"bindPassword"`
	BaseDN       string        `yaml:"baseDN" mapstructure:"baseDN"`
	TLSVerify    bool          `yaml:"tlsVerify" mapstructure:"tlsVerify"`
	Timeout      time.Duration `yaml:"timeout" mapstructure:"timeout"`
	PageSize     int           `yaml:"pageSize" mapstructure:"pageSize"`
}

// AzureConfig holds Azure AD provider configuration
type AzureConfig struct {
	TenantID     string `yaml:"tenantId" mapstructure:"tenantId"`
	ClientID     string `yaml:"clientId" mapstructure:"clientId"`
	ClientSecret string `yaml:"clientSecret" mapstructure:"clientSecret"`
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	JWTPrivateKeyPath string        `yaml:"jwtPrivateKeyPath" mapstructure:"jwtPrivateKeyPath"`
	JWTPublicKeyPath  string        `yaml:"jwtPublicKeyPath" mapstructure:"jwtPublicKeyPath"`
	TokenLifetime     time.Duration `yaml:"tokenLifetime" mapstructure:"tokenLifetime"`

	// Parsed keys (not from config file)
	PrivateKey *rsa.PrivateKey `yaml:"-" mapstructure:"-"`
	PublicKey  *rsa.PublicKey  `yaml:"-" mapstructure:"-"`
}

// LogConfig holds logging configuration
type LogConfig struct {
	Level  string `yaml:"level" mapstructure:"level"`
	Format string `yaml:"format" mapstructure:"format"` // console, json
}

// SaaSConfig holds SaaS integration configuration
type SaaSConfig struct {
	URL     string `yaml:"url" mapstructure:"url"`
	DataDir string `yaml:"dataDir" mapstructure:"dataDir"`
}

// Default returns the default configuration
func Default() *Config {
	return &Config{
		Server: ServerConfig{
			Host:        "0.0.0.0",
			Port:        8443,
			Environment: "development",
			TLSEnabled:  false,
		},
		API: APIConfig{
			Port:      8443,
			RateLimit: 100,
			TLS: TLSConfig{
				Enabled: false,
			},
		},
		LDAP: LDAPConfig{
			TLSVerify: true,
			Timeout:   30 * time.Second,
			PageSize:  1000,
		},
		Auth: AuthConfig{
			TokenLifetime:     30 * 24 * time.Hour, // 30 days
			JWTPrivateKeyPath: "./keys/private.pem",
			JWTPublicKeyPath:  "./keys/public.pem",
		},
		Log: LogConfig{
			Level:  "info",
			Format: "console",
		},
		SaaS: SaaSConfig{
			URL:     "https://api.etcsec.com",
			DataDir: "./data",
		},
	}
}

// Load loads configuration from file and environment
func Load(configFile string) (*Config, error) {
	cfg := Default()

	// If config file specified, use it
	if configFile != "" {
		viper.SetConfigFile(configFile)
	}

	// Read config
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config: %w", err)
		}
		// Config file not found, use defaults
	}

	// Unmarshal into struct
	if err := viper.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	// Validate
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Server port must be valid
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}

	// API port must be valid (legacy)
	if c.API.Port < 1 || c.API.Port > 65535 {
		return fmt.Errorf("invalid API port: %d", c.API.Port)
	}

	// TLS config
	if c.Server.TLSEnabled {
		if c.Server.TLSCertFile == "" || c.Server.TLSKeyFile == "" {
			return fmt.Errorf("TLS enabled but cert/key files not specified")
		}
	}

	return nil
}

// LoadKeys loads RSA keys from files
func (c *Config) LoadKeys() error {
	// Load private key if path is set
	if c.Auth.JWTPrivateKeyPath != "" {
		key, err := LoadPrivateKey(c.Auth.JWTPrivateKeyPath)
		if err != nil {
			// Not fatal - may only have public key for validation
			// return fmt.Errorf("failed to load private key: %w", err)
		} else {
			c.Auth.PrivateKey = key
		}
	}

	// Load public key if path is set
	if c.Auth.JWTPublicKeyPath != "" {
		key, err := LoadPublicKey(c.Auth.JWTPublicKeyPath)
		if err != nil {
			// Not fatal - may only have private key
			// return fmt.Errorf("failed to load public key: %w", err)
		} else {
			c.Auth.PublicKey = key
		}
	}

	// If we have private key but no public key, derive public from private
	if c.Auth.PrivateKey != nil && c.Auth.PublicKey == nil {
		c.Auth.PublicKey = &c.Auth.PrivateKey.PublicKey
	}

	return nil
}

// LoadPrivateKey loads an RSA private key from a PEM file
func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		rsaKey, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not RSA")
		}
		return rsaKey, nil
	}

	return key, nil
}

// LoadPublicKey loads an RSA public key from a PEM file
func LoadPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not RSA")
	}

	return rsaPub, nil
}

// IsProd returns true if running in production mode
func (c *Config) IsProd() bool {
	return os.Getenv("NODE_ENV") == "production" || os.Getenv("GO_ENV") == "production"
}

// WriteExample writes an example config file
func WriteExample(path string) error {
	cfg := Default()

	// Set example values
	cfg.LDAP.URL = "ldaps://dc.example.com:636"
	cfg.LDAP.BindDN = "CN=service,CN=Users,DC=example,DC=com"
	cfg.LDAP.BindPassword = "${LDAP_BIND_PASSWORD}"
	cfg.LDAP.BaseDN = "DC=example,DC=com"

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}
