// Package azure provides an Azure AD / Entra ID client using Microsoft Graph
package azure

import (
	"context"
	"fmt"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/users"
	"github.com/microsoftgraph/msgraph-sdk-go/groups"

	"github.com/etcsec-com/etc-collector/internal/providers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Config holds Azure AD connection configuration
type Config struct {
	TenantID     string `yaml:"tenantId"`
	ClientID     string `yaml:"clientId"`
	ClientSecret string `yaml:"clientSecret"`
}

// Client implements the Provider interface for Azure AD / Entra ID
type Client struct {
	config     Config
	graphClient *msgraphsdk.GraphServiceClient
	mu         sync.RWMutex
	connected  bool
	tenantInfo *TenantInfo
}

// TenantInfo contains Azure AD tenant information
type TenantInfo struct {
	TenantID    string
	DisplayName string
	Domain      string
}

// NewClient creates a new Azure AD client
func NewClient(cfg Config) (*Client, error) {
	if cfg.TenantID == "" {
		return nil, fmt.Errorf("tenant ID is required")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("client ID is required")
	}
	if cfg.ClientSecret == "" {
		return nil, fmt.Errorf("client secret is required")
	}

	return &Client{
		config: cfg,
	}, nil
}

// Type returns the provider type
func (c *Client) Type() providers.ProviderType {
	return providers.ProviderTypeAzure
}

// Connect establishes a connection to Azure AD
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected && c.graphClient != nil {
		return nil
	}

	// Create credential
	cred, err := azidentity.NewClientSecretCredential(
		c.config.TenantID,
		c.config.ClientID,
		c.config.ClientSecret,
		nil,
	)
	if err != nil {
		return providers.NewProviderError(providers.ProviderTypeAzure, "create credential", err)
	}

	// Create Graph client
	client, err := msgraphsdk.NewGraphServiceClientWithCredentials(cred, []string{
		"https://graph.microsoft.com/.default",
	})
	if err != nil {
		return providers.NewProviderError(providers.ProviderTypeAzure, "create client", err)
	}

	c.graphClient = client
	c.connected = true

	return nil
}

// Close closes the Azure AD connection
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.graphClient = nil
	c.connected = false
	return nil
}

// IsConnected returns true if connected
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected && c.graphClient != nil
}

// GetUsers retrieves users from Azure AD
func (c *Client) GetUsers(ctx context.Context, opts providers.QueryOptions) ([]types.User, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected || c.graphClient == nil {
		return nil, fmt.Errorf("not connected")
	}

	// Build query
	requestConfig := &users.UsersRequestBuilderGetRequestConfiguration{
		QueryParameters: &users.UsersRequestBuilderGetQueryParameters{
			Select: []string{
				"id",
				"userPrincipalName",
				"displayName",
				"mail",
				"accountEnabled",
				"createdDateTime",
				"lastSignInDateTime",
				"userType",
				"assignedLicenses",
			},
			Top: int32Ptr(999),
		},
	}

	if opts.Filter != "" {
		requestConfig.QueryParameters.Filter = &opts.Filter
	}

	// Get users
	result, err := c.graphClient.Users().Get(ctx, requestConfig)
	if err != nil {
		return nil, providers.NewProviderError(providers.ProviderTypeAzure, "get users", err)
	}

	// Convert to our types
	var azureUsers []types.User
	for _, u := range result.GetValue() {
		user := convertAzureUser(u)
		azureUsers = append(azureUsers, user)

		if opts.MaxResults > 0 && len(azureUsers) >= opts.MaxResults {
			break
		}
	}

	// Note: Pagination can be implemented using GetOdataNextLink() if needed
	// For now, we return the first page (up to 999 results)

	return azureUsers, nil
}

// GetGroups retrieves groups from Azure AD
func (c *Client) GetGroups(ctx context.Context, opts providers.QueryOptions) ([]types.Group, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected || c.graphClient == nil {
		return nil, fmt.Errorf("not connected")
	}

	// Build query
	requestConfig := &groups.GroupsRequestBuilderGetRequestConfiguration{
		QueryParameters: &groups.GroupsRequestBuilderGetQueryParameters{
			Select: []string{
				"id",
				"displayName",
				"description",
				"groupTypes",
				"securityEnabled",
				"mailEnabled",
				"members",
			},
			Top: int32Ptr(999),
		},
	}

	if opts.Filter != "" {
		requestConfig.QueryParameters.Filter = &opts.Filter
	}

	// Get groups
	result, err := c.graphClient.Groups().Get(ctx, requestConfig)
	if err != nil {
		return nil, providers.NewProviderError(providers.ProviderTypeAzure, "get groups", err)
	}

	// Convert to our types
	var azureGroups []types.Group
	for _, g := range result.GetValue() {
		group := convertAzureGroup(g)
		azureGroups = append(azureGroups, group)

		if opts.MaxResults > 0 && len(azureGroups) >= opts.MaxResults {
			break
		}
	}

	return azureGroups, nil
}

// GetComputers retrieves devices from Azure AD (computers in Azure AD context)
func (c *Client) GetComputers(ctx context.Context, opts providers.QueryOptions) ([]types.Computer, error) {
	// Azure AD uses "devices" instead of computers
	// This requires Device.Read.All permission
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected || c.graphClient == nil {
		return nil, fmt.Errorf("not connected")
	}

	// Get devices via raw request (msgraph-sdk-go device support varies)
	// For now, return empty - device enumeration requires additional setup
	return []types.Computer{}, nil
}

// GetDomainInfo retrieves tenant/domain information
func (c *Client) GetDomainInfo(ctx context.Context) (*types.DomainInfo, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected || c.graphClient == nil {
		return nil, fmt.Errorf("not connected")
	}

	// Get organization info
	org, err := c.graphClient.Organization().Get(ctx, nil)
	if err != nil {
		return nil, providers.NewProviderError(providers.ProviderTypeAzure, "get organization", err)
	}

	info := &types.DomainInfo{}

	if orgs := org.GetValue(); len(orgs) > 0 {
		o := orgs[0]
		if id := o.GetId(); id != nil {
			info.DomainSID = *id // Use tenant ID as "SID"
		}
		if name := o.GetDisplayName(); name != nil {
			info.DomainName = *name
		}

		// Get verified domains
		if domains := o.GetVerifiedDomains(); len(domains) > 0 {
			for _, d := range domains {
				if d.GetIsDefault() != nil && *d.GetIsDefault() {
					if name := d.GetName(); name != nil {
						info.ForestName = *name
					}
				}
			}
		}
	}

	return info, nil
}

// convertAzureUser converts an Azure AD user to our User type
func convertAzureUser(u models.Userable) types.User {
	user := types.User{}

	if id := u.GetId(); id != nil {
		user.ObjectSID = *id
	}
	if upn := u.GetUserPrincipalName(); upn != nil {
		user.UserPrincipalName = *upn
		user.SAMAccountName = extractSAMFromUPN(*upn)
	}
	if name := u.GetDisplayName(); name != nil {
		user.DisplayName = *name
	}
	if mail := u.GetMail(); mail != nil {
		user.Mail = *mail
	}
	if enabled := u.GetAccountEnabled(); enabled != nil {
		user.Disabled = !*enabled
	}
	if created := u.GetCreatedDateTime(); created != nil {
		user.Created = *created
	}

	// LastSignInDateTime requires SignInActivity which needs extra permissions
	// and is in beta API

	return user
}

// convertAzureGroup converts an Azure AD group to our Group type
func convertAzureGroup(g models.Groupable) types.Group {
	group := types.Group{}

	if id := g.GetId(); id != nil {
		group.ObjectSID = *id
	}
	if name := g.GetDisplayName(); name != nil {
		group.SAMAccountName = *name
	}
	if desc := g.GetDescription(); desc != nil {
		group.Description = *desc
	}

	return group
}

// extractSAMFromUPN extracts sAMAccountName from UPN (user@domain.com -> user)
func extractSAMFromUPN(upn string) string {
	for i, c := range upn {
		if c == '@' {
			return upn[:i]
		}
	}
	return upn
}

// int32Ptr returns a pointer to an int32
func int32Ptr(i int32) *int32 {
	return &i
}
