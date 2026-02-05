package other

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AdminSdHolderModifiedDetector detects modified AdminSDHolder permissions
type AdminSdHolderModifiedDetector struct {
	audit.BaseDetector
}

// NewAdminSdHolderModifiedDetector creates a new detector
func NewAdminSdHolderModifiedDetector() *AdminSdHolderModifiedDetector {
	return &AdminSdHolderModifiedDetector{
		BaseDetector: audit.NewBaseDetector("ADMIN_SD_HOLDER_MODIFIED", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *AdminSdHolderModifiedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// This would require reading the nTSecurityDescriptor of AdminSDHolder
	// For now, check if domain has indicators of modification
	count := 0
	if data.DomainInfo != nil && data.DomainInfo.AdminSDHolderModified {
		count = 1
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "AdminSDHolder Review Required",
		Description: "AdminSDHolder permissions should be reviewed. Modifications propagate to all protected accounts (Domain Admins, Enterprise Admins, etc.) via SDProp process.",
		Count:       count,
		Details: map[string]interface{}{
			"recommendation": "Compare AdminSDHolder ACL against baseline. Look for non-standard principals with permissions.",
			"checkCommand":   "Get-ADObject 'CN=AdminSDHolder,CN=System,DC=...' -Properties nTSecurityDescriptor",
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAdminSdHolderModifiedDetector())
}
