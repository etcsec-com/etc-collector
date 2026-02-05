// Package ldap provides an LDAP client for Active Directory
package ldap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/providers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Config holds LDAP connection configuration
type Config struct {
	URL          string        `yaml:"url"`
	BindDN       string        `yaml:"bindDN"`
	BindPassword string        `yaml:"bindPassword"`
	BaseDN       string        `yaml:"baseDN"`
	TLSVerify    bool          `yaml:"tlsVerify"`
	TLSCACert    string        `yaml:"tlsCACert"` // Path to CA certificate file
	Timeout      time.Duration `yaml:"timeout"`
	PageSize     int           `yaml:"pageSize"`
}

// Client implements the Provider interface for LDAP/Active Directory
type Client struct {
	config    Config
	conn      *ldap.Conn
	mu        sync.RWMutex
	connected bool

	// Cached domain info
	domainInfo *types.DomainInfo
}

// NewClient creates a new LDAP client
func NewClient(cfg Config) (*Client, error) {
	// Set defaults
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.PageSize == 0 {
		cfg.PageSize = 1000
	}

	// Validate URL
	if cfg.URL == "" {
		return nil, fmt.Errorf("LDAP URL is required")
	}

	return &Client{
		config: cfg,
	}, nil
}

// Type returns the provider type
func (c *Client) Type() providers.ProviderType {
	return providers.ProviderTypeLDAP
}

// Connect establishes a connection to the LDAP server
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected && c.conn != nil {
		return nil
	}

	// Parse URL
	u, err := url.Parse(c.config.URL)
	if err != nil {
		return providers.NewProviderError(providers.ProviderTypeLDAP, "parse url", err)
	}

	// Determine port
	host := u.Host
	if !strings.Contains(host, ":") {
		if u.Scheme == "ldaps" {
			host += ":636"
		} else {
			host += ":389"
		}
	}

	// Connect with TLS if ldaps
	var conn *ldap.Conn
	if u.Scheme == "ldaps" {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: !c.config.TLSVerify,
			ServerName:         strings.Split(u.Host, ":")[0],
		}

		// Load CA certificate if provided
		if c.config.TLSCACert != "" && c.config.TLSVerify {
			caCert, err := os.ReadFile(c.config.TLSCACert)
			if err != nil {
				return providers.NewProviderError(providers.ProviderTypeLDAP, "read ca cert", err)
			}
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return providers.NewProviderError(providers.ProviderTypeLDAP, "parse ca cert", fmt.Errorf("failed to parse CA certificate"))
			}
			tlsConfig.RootCAs = caCertPool
			tlsConfig.InsecureSkipVerify = false
		}

		conn, err = ldap.DialURL(c.config.URL, ldap.DialWithTLSConfig(tlsConfig))
	} else {
		conn, err = ldap.DialURL(c.config.URL)
	}

	if err != nil {
		return providers.NewProviderError(providers.ProviderTypeLDAP, "connect", err)
	}

	// Set timeout
	conn.SetTimeout(c.config.Timeout)

	// Bind
	if c.config.BindDN != "" {
		if err := conn.Bind(c.config.BindDN, c.config.BindPassword); err != nil {
			conn.Close()
			return providers.NewProviderError(providers.ProviderTypeLDAP, "bind", err)
		}
	}

	c.conn = conn
	c.connected = true

	return nil
}

// Close closes the LDAP connection
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	c.connected = false
	return nil
}

// IsConnected returns true if connected
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected && c.conn != nil
}

// search performs a paged LDAP search
func (c *Client) search(ctx context.Context, baseDN, filter string, attrs []string, maxResults int) ([]*ldap.Entry, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected || c.conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	// Use default base DN if not specified
	if baseDN == "" {
		baseDN = c.config.BaseDN
	}

	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, // No size limit (we'll handle via paging)
		int(c.config.Timeout.Seconds()),
		false,
		filter,
		attrs,
		nil,
	)

	// Perform paged search
	var entries []*ldap.Entry
	pagingControl := ldap.NewControlPaging(uint32(c.config.PageSize))

	for {
		searchReq.Controls = []ldap.Control{pagingControl}

		result, err := c.conn.Search(searchReq)
		if err != nil {
			return nil, err
		}

		entries = append(entries, result.Entries...)

		// Check if we've hit max results
		if maxResults > 0 && len(entries) >= maxResults {
			entries = entries[:maxResults]
			break
		}

		// Get paging control from response
		ctrl := ldap.FindControl(result.Controls, ldap.ControlTypePaging)
		if ctrl == nil {
			break
		}

		pagingCtrl, ok := ctrl.(*ldap.ControlPaging)
		if !ok || len(pagingCtrl.Cookie) == 0 {
			break
		}

		pagingControl.SetCookie(pagingCtrl.Cookie)
	}

	return entries, nil
}

// GetUsers retrieves users from Active Directory
func (c *Client) GetUsers(ctx context.Context, opts providers.QueryOptions) ([]types.User, error) {
	filter := opts.Filter
	if filter == "" {
		filter = "(&(objectClass=user)(objectCategory=person))"
	}

	attrs := opts.Attributes
	if len(attrs) == 0 {
		attrs = userAttributes
	}

	entries, err := c.search(ctx, c.config.BaseDN, filter, attrs, opts.MaxResults)
	if err != nil {
		return nil, providers.NewProviderError(providers.ProviderTypeLDAP, "get users", err)
	}

	users := make([]types.User, 0, len(entries))
	for _, entry := range entries {
		user := parseUser(entry)
		users = append(users, user)
	}

	return users, nil
}

// GetGroups retrieves groups from Active Directory
func (c *Client) GetGroups(ctx context.Context, opts providers.QueryOptions) ([]types.Group, error) {
	filter := opts.Filter
	if filter == "" {
		filter = "(objectClass=group)"
	}

	attrs := opts.Attributes
	if len(attrs) == 0 {
		attrs = groupAttributes
	}

	entries, err := c.search(ctx, c.config.BaseDN, filter, attrs, opts.MaxResults)
	if err != nil {
		return nil, providers.NewProviderError(providers.ProviderTypeLDAP, "get groups", err)
	}

	groups := make([]types.Group, 0, len(entries))
	for _, entry := range entries {
		group := parseGroup(entry)
		groups = append(groups, group)
	}

	return groups, nil
}

// GetComputers retrieves computer accounts from Active Directory
func (c *Client) GetComputers(ctx context.Context, opts providers.QueryOptions) ([]types.Computer, error) {
	filter := opts.Filter
	if filter == "" {
		filter = "(objectClass=computer)"
	}

	attrs := opts.Attributes
	if len(attrs) == 0 {
		attrs = computerAttributes
	}

	entries, err := c.search(ctx, c.config.BaseDN, filter, attrs, opts.MaxResults)
	if err != nil {
		return nil, providers.NewProviderError(providers.ProviderTypeLDAP, "get computers", err)
	}

	computers := make([]types.Computer, 0, len(entries))
	for _, entry := range entries {
		computer := parseComputer(entry)
		computers = append(computers, computer)
	}

	return computers, nil
}

// GetDomainInfo retrieves domain-level information
func (c *Client) GetDomainInfo(ctx context.Context) (*types.DomainInfo, error) {
	if c.domainInfo != nil {
		return c.domainInfo, nil
	}

	// Get domain info from RootDSE and domain object
	info := &types.DomainInfo{
		DomainDN: c.config.BaseDN,
	}

	// Query RootDSE for naming contexts
	rootDSE, err := c.search(ctx, "", "(objectClass=*)", []string{
		"defaultNamingContext",
		"rootDomainNamingContext",
		"configurationNamingContext",
		"schemaNamingContext",
		"dnsHostName",
	}, 1)
	if err == nil && len(rootDSE) > 0 {
		entry := rootDSE[0]
		info.DomainDN = entry.GetAttributeValue("defaultNamingContext")
	}

	// Query domain object for more details
	domainFilter := "(objectClass=domain)"
	domainEntries, err := c.search(ctx, c.config.BaseDN, domainFilter, []string{
		"objectSid",
		"name",
		"msDS-Behavior-Version",
		"minPwdLength",
		"pwdHistoryLength",
		"maxPwdAge",
		"lockoutThreshold",
		"lockoutDuration",
		"ms-DS-MachineAccountQuota",
	}, 1)

	if err == nil && len(domainEntries) > 0 {
		entry := domainEntries[0]
		info.DomainSID = decodeSID(entry.GetRawAttributeValue("objectSid"))
		info.DomainName = entry.GetAttributeValue("name")
		info.MinPasswordLength = getIntAttr(entry, "minPwdLength")
		info.PasswordHistoryLength = getIntAttr(entry, "pwdHistoryLength")
		info.LockoutThreshold = getIntAttr(entry, "lockoutThreshold")
		info.MachineAccountQuota = getIntAttr(entry, "ms-DS-MachineAccountQuota")

		// Functional level
		level := getIntAttr(entry, "msDS-Behavior-Version")
		info.FunctionalLevel = functionalLevelToString(level)
	}

	// Get domain controllers
	dcFilter := "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
	dcEntries, err := c.search(ctx, c.config.BaseDN, dcFilter, []string{"dNSHostName"}, 0)
	if err == nil {
		for _, entry := range dcEntries {
			if dns := entry.GetAttributeValue("dNSHostName"); dns != "" {
				info.DomainControllers = append(info.DomainControllers, dns)
			}
		}
	}

	c.domainInfo = info
	return info, nil
}

// GetGPOs retrieves Group Policy Objects
func (c *Client) GetGPOs(ctx context.Context, opts providers.QueryOptions) ([]types.GPO, error) {
	filter := "(objectClass=groupPolicyContainer)"
	attrs := []string{
		"distinguishedName",
		"displayName",
		"name",
		"gPCFileSysPath",
		"flags",
	}

	entries, err := c.search(ctx, c.config.BaseDN, filter, attrs, 0)
	if err != nil {
		return nil, providers.NewProviderError(providers.ProviderTypeLDAP, "get gpos", err)
	}

	gpos := make([]types.GPO, 0, len(entries))
	for _, entry := range entries {
		name := entry.GetAttributeValue("name")
		gpo := types.GPO{
			DN:                entry.DN,
			DistinguishedName: entry.DN, // Alias
			CN:                name,      // Common name (GUID format: {xxx-xxx-xxx})
			Name:              name,
			DisplayName:       entry.GetAttributeValue("displayName"),
			GUID:              name,
			FilePath:          entry.GetAttributeValue("gPCFileSysPath"),
		}

		flags := getIntAttr(entry, "flags")
		gpo.UserEnabled = (flags & 1) == 0
		gpo.ComputerEnabled = (flags & 2) == 0
		gpo.Enabled = gpo.UserEnabled || gpo.ComputerEnabled

		gpos = append(gpos, gpo)
	}

	return gpos, nil
}

// GetGPOLinks retrieves GPO links from OUs, Sites, and Domain
func (c *Client) GetGPOLinks(ctx context.Context) ([]audit.GPOLink, error) {
	// Search for objects that can have GPO links (OUs, Sites, Domain)
	filter := "(|(objectClass=organizationalUnit)(objectClass=domainDNS)(objectClass=site))"
	attrs := []string{
		"distinguishedName",
		"gPLink",
		"gPOptions",
	}

	entries, err := c.search(ctx, c.config.BaseDN, filter, attrs, 0)
	if err != nil {
		return nil, providers.NewProviderError(providers.ProviderTypeLDAP, "get gpo links", err)
	}

	// Also search in Configuration partition for Sites
	configDN := "CN=Sites,CN=Configuration," + c.config.BaseDN
	siteEntries, _ := c.search(ctx, configDN, "(objectClass=site)", attrs, 0)
	entries = append(entries, siteEntries...)

	var links []audit.GPOLink
	for _, entry := range entries {
		gpLink := entry.GetAttributeValue("gPLink")
		if gpLink == "" {
			continue
		}

		// Parse gPLink format: [LDAP://cn={GUID},cn=policies,cn=system,DC=...;flags][...]
		parsedLinks := parseGPLinks(gpLink, entry.DN)
		links = append(links, parsedLinks...)
	}

	return links, nil
}

// parseGPLinks parses the gPLink attribute format
// Format: [LDAP://CN={GUID},CN=Policies,CN=System,DC=...;flags]
// Flags: 0=enabled, 1=disabled, 2=enforced
func parseGPLinks(gpLink string, linkedTo string) []audit.GPOLink {
	var links []audit.GPOLink
	order := 0

	// Split by ][ to get individual links
	for len(gpLink) > 0 {
		start := strings.Index(gpLink, "[LDAP://")
		if start == -1 {
			break
		}
		end := strings.Index(gpLink[start:], "]")
		if end == -1 {
			break
		}
		end += start

		linkStr := gpLink[start+8 : end] // Skip "[LDAP://"
		gpLink = gpLink[end+1:]

		// Split by semicolon: DN;flags
		parts := strings.SplitN(linkStr, ";", 2)
		if len(parts) != 2 {
			continue
		}

		gpoDN := parts[0]
		flags, _ := strconv.Atoi(parts[1])

		// Extract CN (GUID with braces) from DN (CN={GUID},CN=Policies,...)
		gpoCN := ""
		gpoGuid := ""
		if idx := strings.Index(strings.ToUpper(gpoDN), "CN={"); idx != -1 {
			endIdx := strings.Index(gpoDN[idx+3:], ",")
			if endIdx != -1 {
				gpoCN = gpoDN[idx+3 : idx+3+endIdx] // Extract {GUID}
				gpoGuid = strings.Trim(gpoCN, "{}")  // GUID without braces
			}
		}

		link := audit.GPOLink{
			GPOCN:       gpoCN,  // CN = {GUID}
			GPOGuid:     gpoGuid,
			LinkedTo:    linkedTo,
			LinkEnabled: (flags & 1) == 0,
			Disabled:    (flags & 1) != 0,
			Enforced:    (flags & 2) != 0,
			Order:       order,
		}
		links = append(links, link)
		order++
	}

	return links
}

// GetGPOAcls retrieves ACLs on GPO objects
func (c *Client) GetGPOAcls(ctx context.Context, gpoDNs []string) ([]audit.GPOAcl, error) {
	if len(gpoDNs) == 0 {
		return nil, nil
	}

	// Get security descriptors for GPOs
	acls, err := c.GetACLs(ctx, gpoDNs)
	if err != nil {
		return nil, err
	}

	// Convert ACLEntries to GPOAcl format
	var gpoAcls []audit.GPOAcl
	for _, acl := range acls {
		gpoAcl := audit.GPOAcl{
			GPODN:      acl.ObjectDN,
			Trustee:    acl.Trustee,
			TrusteeSID: acl.Trustee, // Trustee contains SID
			AccessMask: acl.AccessMask,
			AceType:    acl.AceType,
		}
		gpoAcls = append(gpoAcls, gpoAcl)
	}

	return gpoAcls, nil
}

// GetTrusts retrieves domain trusts
func (c *Client) GetTrusts(ctx context.Context, opts providers.QueryOptions) ([]types.Trust, error) {
	filter := "(objectClass=trustedDomain)"
	attrs := []string{
		"distinguishedName",
		"name",
		"trustDirection",
		"trustType",
		"trustAttributes",
	}

	entries, err := c.search(ctx, c.config.BaseDN, filter, attrs, 0)
	if err != nil {
		return nil, providers.NewProviderError(providers.ProviderTypeLDAP, "get trusts", err)
	}

	trusts := make([]types.Trust, 0, len(entries))
	for _, entry := range entries {
		trust := types.Trust{
			TargetDomain: entry.GetAttributeValue("name"),
		}

		// Parse trust direction
		direction := getIntAttr(entry, "trustDirection")
		switch direction {
		case 1:
			trust.TrustDirection = "Inbound"
		case 2:
			trust.TrustDirection = "Outbound"
		case 3:
			trust.TrustDirection = "Bidirectional"
		}

		// Parse trust type
		trustType := getIntAttr(entry, "trustType")
		switch trustType {
		case 1:
			trust.TrustType = "Downlevel"
		case 2:
			trust.TrustType = "Uplevel"
		case 3:
			trust.TrustType = "MIT"
		case 4:
			trust.TrustType = "DCE"
		}

		// Trust attributes
		attrs := getIntAttr(entry, "trustAttributes")
		trust.SIDFiltering = (attrs & 4) != 0
		trust.SelectiveAuth = (attrs & 16) != 0

		trusts = append(trusts, trust)
	}

	return trusts, nil
}

// GetCertTemplates retrieves certificate templates
func (c *Client) GetCertTemplates(ctx context.Context, opts providers.QueryOptions) ([]types.CertTemplate, error) {
	// Certificate templates are in the Configuration partition
	configDN := "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration," + c.config.BaseDN

	filter := "(objectClass=pKICertificateTemplate)"
	attrs := []string{
		"distinguishedName",
		"name",
		"displayName",
		"msPKI-Cert-Template-OID",
		"msPKI-Enrollment-Flag",
		"msPKI-RA-Signature",
		"pKIExtendedKeyUsage",
		"msPKI-Certificate-Name-Flag",
		"revision",
	}

	entries, err := c.search(ctx, configDN, filter, attrs, 0)
	if err != nil {
		// May not have access to Configuration partition
		return nil, nil
	}

	templates := make([]types.CertTemplate, 0, len(entries))
	for _, entry := range entries {
		template := types.CertTemplate{
			DN:                   entry.DN,
			Name:                 entry.GetAttributeValue("name"),
			DisplayName:          entry.GetAttributeValue("displayName"),
			OID:                  entry.GetAttributeValue("msPKI-Cert-Template-OID"),
			EnrollmentFlag:       getIntAttr(entry, "msPKI-Enrollment-Flag"),
			AuthorizedSignatures: getIntAttr(entry, "msPKI-RA-Signature"),
			SubjectNameFlag:      getIntAttr(entry, "msPKI-Certificate-Name-Flag"),
			SchemaVersion:        getIntAttr(entry, "revision"),
			ExtendedKeyUsage:     entry.GetAttributeValues("pKIExtendedKeyUsage"),
		}

		// Check if manager approval required
		template.RequiresManagerApproval = (template.EnrollmentFlag & 2) != 0

		templates = append(templates, template)
	}

	return templates, nil
}

// GetObjectACL retrieves the ACL for a specific object
func (c *Client) GetObjectACL(ctx context.Context, dn string) ([]types.ACE, error) {
	entries, err := c.getSecurityDescriptors(ctx, []string{dn})
	if err != nil {
		return nil, providers.NewProviderError(providers.ProviderTypeLDAP, "get acl", err)
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("object not found: %s", dn)
	}

	// Convert ACLEntry to ACE
	var aces []types.ACE
	for _, entry := range entries {
		aces = append(aces, types.ACE{
			PrincipalSID: entry.Trustee,
			AccessMask:   entry.AccessMask,
			AceType:      entry.AceType,
			ObjectType:   entry.ObjectType,
		})
	}
	return aces, nil
}

// GetACLs retrieves ACLs for multiple objects (users, groups, computers, etc.)
// This is the bulk ACL collection method used by the audit engine
func (c *Client) GetACLs(ctx context.Context, objectDNs []string) ([]types.ACLEntry, error) {
	if len(objectDNs) == 0 {
		return nil, nil
	}

	return c.getSecurityDescriptors(ctx, objectDNs)
}

// getSecurityDescriptors fetches and parses security descriptors for multiple DNs
// Uses LDAP_SERVER_SD_FLAGS_OID control (1.2.840.113556.1.4.801) with flags 0x07
// to request OWNER, GROUP, and DACL in the security descriptor
func (c *Client) getSecurityDescriptors(ctx context.Context, dns []string) ([]types.ACLEntry, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected || c.conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	var allEntries []types.ACLEntry

	// LDAP_SERVER_SD_FLAGS_OID control
	// OID: 1.2.840.113556.1.4.801
	// Value: BER INTEGER encoding: 0x02 (INTEGER tag), 0x01 (length), 0x07 (value)
	// 0x07 = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
	// critical: false (must match what ldapts uses)
	sdFlagsControl := ldap.NewControlString("1.2.840.113556.1.4.801", false, string([]byte{0x02, 0x01, 0x07}))

	// Process in batches of 100 to avoid overwhelming the server
	batchSize := 100
	for i := 0; i < len(dns); i += batchSize {
		end := i + batchSize
		if end > len(dns) {
			end = len(dns)
		}
		batch := dns[i:end]

		for _, dn := range batch {
			// Create search request for single object
			searchReq := ldap.NewSearchRequest(
				dn,
				ldap.ScopeBaseObject,
				ldap.NeverDerefAliases,
				1,
				int(c.config.Timeout.Seconds()),
				false,
				"(objectClass=*)",
				[]string{"nTSecurityDescriptor"},
				[]ldap.Control{sdFlagsControl},
			)

			result, err := c.conn.Search(searchReq)
			if err != nil {
				// Skip objects we can't access (permission denied, not found, etc.)
				continue
			}

			for _, entry := range result.Entries {
				// Get raw binary security descriptor
				sdBytes := entry.GetRawAttributeValue("nTSecurityDescriptor")
				if len(sdBytes) == 0 {
					continue
				}

				// Parse security descriptor into ACL entries
				aclEntries := ParseSecurityDescriptor(sdBytes, dn)
				allEntries = append(allEntries, aclEntries...)
			}
		}
	}

	return allEntries, nil
}

// functionalLevelToString converts functional level to string
func functionalLevelToString(level int) string {
	switch level {
	case 0:
		return "2000"
	case 1:
		return "2003 Interim"
	case 2:
		return "2003"
	case 3:
		return "2008"
	case 4:
		return "2008 R2"
	case 5:
		return "2012"
	case 6:
		return "2012 R2"
	case 7:
		return "2016"
	default:
		return fmt.Sprintf("Unknown (%d)", level)
	}
}
