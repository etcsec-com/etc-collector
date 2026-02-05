package signing

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// LdapChannelBindingDisabledDetector detects if LDAP channel binding is disabled
type LdapChannelBindingDisabledDetector struct {
	audit.BaseDetector
}

// NewLdapChannelBindingDisabledDetector creates a new detector
func NewLdapChannelBindingDisabledDetector() *LdapChannelBindingDisabledDetector {
	return &LdapChannelBindingDisabledDetector{
		BaseDetector: audit.NewBaseDetector("LDAP_CHANNEL_BINDING_DISABLED", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *LdapChannelBindingDisabledDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// This requires GPO/registry settings - for now, flag for manual review
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "LDAP Channel Binding Configuration Unknown",
		Description: "Unable to determine LDAP channel binding configuration. Manual review recommended.",
		Count:       0,
		Details: map[string]interface{}{
			"note":           "GPO/Registry settings not available via LDAP. Check LdapEnforceChannelBinding registry value manually.",
			"recommendation": "Configure 'Domain controller: LDAP server channel binding token requirements' to 'Always'.",
			"registryPath":   "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters\\LdapEnforceChannelBinding",
			"requiredValue":  2,
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewLdapChannelBindingDisabledDetector())
}
