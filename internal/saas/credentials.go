package saas

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Credentials stores authentication information
type Credentials struct {
	CollectorID  string `json:"collectorId"`
	Token        string `json:"token"`
	RefreshToken string `json:"refreshToken,omitempty"`
	SaaSURL      string `json:"saasUrl"`
}

// CredentialStore manages persistent credentials
type CredentialStore struct {
	path string
}

// NewCredentialStore creates a new credential store
func NewCredentialStore(dataDir string) *CredentialStore {
	return &CredentialStore{
		path: filepath.Join(dataDir, "credentials.json"),
	}
}

// Save persists credentials to disk
func (s *CredentialStore) Save(creds *Credentials) error {
	// Ensure directory exists
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}

	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal credentials: %w", err)
	}

	// Write with restricted permissions
	if err := os.WriteFile(s.path, data, 0600); err != nil {
		return fmt.Errorf("write credentials: %w", err)
	}

	return nil
}

// Load reads credentials from disk
func (s *CredentialStore) Load() (*Credentials, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // Not enrolled yet
		}
		return nil, fmt.Errorf("read credentials: %w", err)
	}

	var creds Credentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("unmarshal credentials: %w", err)
	}

	return &creds, nil
}

// Delete removes stored credentials
func (s *CredentialStore) Delete() error {
	if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete credentials: %w", err)
	}
	return nil
}

// Exists returns true if credentials are stored
func (s *CredentialStore) Exists() bool {
	_, err := os.Stat(s.path)
	return err == nil
}

// Path returns the credentials file path
func (s *CredentialStore) Path() string {
	return s.path
}
