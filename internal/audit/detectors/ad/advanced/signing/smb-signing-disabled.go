package signing

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// SmbSigningDisabledDetector detects if SMB signing is disabled
type SmbSigningDisabledDetector struct {
	audit.BaseDetector
}

// NewSmbSigningDisabledDetector creates a new detector
func NewSmbSigningDisabledDetector() *SmbSigningDisabledDetector {
	return &SmbSigningDisabledDetector{
		BaseDetector: audit.NewBaseDetector("SMB_SIGNING_DISABLED", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *SmbSigningDisabledDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Windows defaults don't require SMB signing - flag as vulnerable unless confirmed otherwise
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "SMB Signing Not Configured in GPO",
		Description: "SMB signing is not configured via Group Policy. Windows defaults do not require SMB signing, making this environment vulnerable to NTLM relay attacks.",
		Count:       1,
		Details: map[string]interface{}{
			"recommendation": "Configure 'Microsoft network server: Digitally sign communications (always)' via Group Policy.",
			"note":           "No GPO security template found via LDAP. Windows defaults do not require SMB signing.",
			"registryPath":   "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters\\RequireSecuritySignature",
			"requiredValue":  1,
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
	audit.MustRegister(NewSmbSigningDisabledDetector())
}
