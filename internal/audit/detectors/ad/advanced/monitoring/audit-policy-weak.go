package monitoring

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AuditPolicyWeakDetector detects weak or incomplete audit policies
type AuditPolicyWeakDetector struct {
	audit.BaseDetector
}

// NewAuditPolicyWeakDetector creates a new detector
func NewAuditPolicyWeakDetector() *AuditPolicyWeakDetector {
	return &AuditPolicyWeakDetector{
		BaseDetector: audit.NewBaseDetector("AUDIT_POLICY_WEAK", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *AuditPolicyWeakDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Critical audit categories that should be enabled
	criticalAuditCategories := []string{
		"Account Logon",
		"Account Management",
		"Logon/Logoff",
		"Object Access",
		"Policy Change",
		"Privilege Use",
		"System",
	}

	// This would require GPO settings from SYSVOL - for now, flag for manual review
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Audit Policy Configuration Unknown",
		Description: "Unable to determine audit policy configuration. Manual review recommended.",
		Count:       0,
		Details: map[string]interface{}{
			"note":               "GPO audit settings not available via LDAP. Check Advanced Audit Policy Configuration manually.",
			"requiredCategories": criticalAuditCategories,
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAuditPolicyWeakDetector())
}
