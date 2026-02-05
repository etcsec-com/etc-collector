// Package audit provides AD security vulnerability detection
package audit

import (
	"context"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DetectorCategory represents a detector category
type DetectorCategory string

const (
	CategoryAccounts       DetectorCategory = "accounts"
	CategoryGroups         DetectorCategory = "groups"
	CategoryComputers      DetectorCategory = "computers"
	CategoryPermissions    DetectorCategory = "permissions"
	CategoryKerberos       DetectorCategory = "kerberos"
	CategoryPassword       DetectorCategory = "password"
	CategoryGPO            DetectorCategory = "gpo"
	CategoryTrusts         DetectorCategory = "trusts"
	CategoryADCS           DetectorCategory = "adcs"
	CategoryAttackPaths    DetectorCategory = "attack-paths"
	CategoryMonitoring     DetectorCategory = "monitoring"
	CategoryNetwork        DetectorCategory = "network"
	CategoryCompliance     DetectorCategory = "compliance"
	CategoryAdvanced       DetectorCategory = "advanced"
	CategoryConfig         DetectorCategory = "config"
	CategoryIdentity       DetectorCategory = "identity"       // Azure AD
	CategoryApplications   DetectorCategory = "applications"   // Azure AD
	CategoryPrivilegedAccess DetectorCategory = "privilegedAccess" // Azure AD
)

// Detector is the common interface for all detectors
type Detector interface {
	// ID returns the unique identifier (e.g., "STALE_ACCOUNT")
	ID() string

	// Category returns the detector category
	Category() DetectorCategory

	// Detect executes the detection and returns findings
	Detect(ctx context.Context, data *DetectorData) []types.Finding
}

// GPOLink represents a link between a GPO and an OU/Site
type GPOLink struct {
	GPOCN       string `json:"gpoCN"`
	GPOGuid     string `json:"gpoGuid,omitempty"` // Alias
	LinkedTo    string `json:"linkedTo"` // DN of OU/Site
	LinkEnabled bool   `json:"linkEnabled"`
	Disabled    bool   `json:"disabled,omitempty"` // Inverse of LinkEnabled
	Enforced    bool   `json:"enforced"`
	Order       int    `json:"order"`
}

// GPOAcl represents an ACL on a GPO
type GPOAcl struct {
	GPODN       string `json:"gpoDN"`
	Trustee     string `json:"trustee"`
	TrusteeSID  string `json:"trusteeSID,omitempty"` // SID of trustee
	AccessMask  int    `json:"accessMask"`
	AceType     string `json:"aceType"`
}

// Site represents an AD site
type Site struct {
	Name              string   `json:"name"`
	DistinguishedName string   `json:"distinguishedName"`
	Description       string   `json:"description,omitempty"`
	Servers           []string `json:"servers,omitempty"` // DCs in this site
}

// Subnet represents an AD subnet
type Subnet struct {
	Name              string `json:"name"`
	DistinguishedName string `json:"distinguishedName"`
	SiteDN            string `json:"siteDN"` // Reference to Site DN
	Description       string `json:"description,omitempty"`
}

// DetectorData contains all data needed for detection
type DetectorData struct {
	// AD Objects
	Users             []types.User
	Groups            []types.Group
	Computers         []types.Computer
	GPOs              []types.GPO
	Trusts            []types.Trust
	CertTemplates     []types.CertTemplate
	ACLEntries        []types.ACLEntry
	DomainControllers []types.Computer

	// GPO related
	GPOLinks []GPOLink
	GPOAcls  []GPOAcl

	// Sites and Subnets
	Sites   []Site
	Subnets []Subnet

	// Domain information
	DomainInfo *types.DomainInfo

	// Options
	IncludeDetails bool
}

// BaseDetector provides common implementation
type BaseDetector struct {
	id       string
	category DetectorCategory
}

// NewBaseDetector creates a new base detector
func NewBaseDetector(id string, category DetectorCategory) BaseDetector {
	return BaseDetector{
		id:       id,
		category: category,
	}
}

// ID returns the detector ID
func (d *BaseDetector) ID() string {
	return d.id
}

// Category returns the detector category
func (d *BaseDetector) Category() DetectorCategory {
	return d.category
}
