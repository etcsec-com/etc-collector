package signing

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// LdapSigningDisabledDetector detects if LDAP signing is disabled
type LdapSigningDisabledDetector struct {
	audit.BaseDetector
}

// NewLdapSigningDisabledDetector creates a new detector
func NewLdapSigningDisabledDetector() *LdapSigningDisabledDetector {
	return &LdapSigningDisabledDetector{
		BaseDetector: audit.NewBaseDetector("LDAP_SIGNING_DISABLED", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *LdapSigningDisabledDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Windows defaults don't require LDAP signing - flag as vulnerable unless confirmed otherwise
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "LDAP Signing Not Configured in GPO",
		Description: "LDAP signing is not configured via Group Policy. Windows defaults do not require LDAP signing, making this environment vulnerable to LDAP relay attacks.",
		Count:       1,
		Details: map[string]interface{}{
			"recommendation": "Configure 'Domain controller: LDAP server signing requirements' to 'Require signing' via Group Policy.",
			"note":           "No GPO security template found via LDAP. Windows defaults do not require LDAP signing.",
			"registryPath":   "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters\\LDAPServerIntegrity",
			"requiredValue":  2,
		},
	}

	if data.IncludeDetails && data.DomainInfo != nil {
		finding.AffectedEntities = []types.AffectedEntity{{
			Type:           "domain",
			SAMAccountName: data.DomainInfo.DN,
		}}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewLdapSigningDisabledDetector())
}
