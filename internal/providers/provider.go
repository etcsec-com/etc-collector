// Package providers defines the interface for identity providers
package providers

import (
	"context"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ProviderType represents the type of provider
type ProviderType string

const (
	ProviderTypeLDAP  ProviderType = "ldap"
	ProviderTypeAzure ProviderType = "azure"
)

// QueryOptions contains options for querying objects
type QueryOptions struct {
	MaxResults int      // Maximum number of results (0 = unlimited)
	Filter     string   // Custom LDAP filter or OData filter
	Attributes []string // Specific attributes to retrieve
	PageSize   int      // Page size for pagination
}

// Provider is the interface that all identity providers must implement
type Provider interface {
	// Type returns the provider type
	Type() ProviderType

	// Connect establishes a connection to the provider
	Connect(ctx context.Context) error

	// Close closes the connection
	Close() error

	// IsConnected returns true if connected
	IsConnected() bool

	// GetUsers retrieves users from the directory
	GetUsers(ctx context.Context, opts QueryOptions) ([]types.User, error)

	// GetGroups retrieves groups from the directory
	GetGroups(ctx context.Context, opts QueryOptions) ([]types.Group, error)

	// GetComputers retrieves computer accounts from the directory
	GetComputers(ctx context.Context, opts QueryOptions) ([]types.Computer, error)

	// GetDomainInfo retrieves domain-level information
	GetDomainInfo(ctx context.Context) (*types.DomainInfo, error)
}

// ExtendedProvider provides additional capabilities beyond basic Provider
type ExtendedProvider interface {
	Provider

	// GetGPOs retrieves Group Policy Objects
	GetGPOs(ctx context.Context) ([]types.GPO, error)

	// GetTrusts retrieves domain trusts
	GetTrusts(ctx context.Context) ([]types.Trust, error)

	// GetCertTemplates retrieves certificate templates (AD CS)
	GetCertTemplates(ctx context.Context) ([]types.CertTemplate, error)

	// GetObjectACL retrieves the ACL for a specific object
	GetObjectACL(ctx context.Context, dn string) ([]types.ACE, error)
}

// ProviderInfo contains metadata about a provider
type ProviderInfo struct {
	Type        ProviderType `json:"type"`
	Connected   bool         `json:"connected"`
	Domain      string       `json:"domain,omitempty"`
	Server      string       `json:"server,omitempty"`
	TenantID    string       `json:"tenantId,omitempty"`
	LastConnect string       `json:"lastConnect,omitempty"`
	Error       string       `json:"error,omitempty"`
}

// ProviderError represents a provider-specific error
type ProviderError struct {
	Provider ProviderType
	Op       string
	Err      error
}

func (e *ProviderError) Error() string {
	return string(e.Provider) + ": " + e.Op + ": " + e.Err.Error()
}

func (e *ProviderError) Unwrap() error {
	return e.Err
}

// NewProviderError creates a new provider error
func NewProviderError(provider ProviderType, op string, err error) *ProviderError {
	return &ProviderError{
		Provider: provider,
		Op:       op,
		Err:      err,
	}
}
