package monitoring

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AuditPolicyChangeDetector checks if policy change events are audited
type AuditPolicyChangeDetector struct {
	audit.BaseDetector
}

// NewAuditPolicyChangeDetector creates a new detector
func NewAuditPolicyChangeDetector() *AuditPolicyChangeDetector {
	return &AuditPolicyChangeDetector{
		BaseDetector: audit.NewBaseDetector("AUDIT_POLICY_CHANGE_DISABLED", audit.CategoryMonitoring),
	}
}

// Detect executes the detection
func (d *AuditPolicyChangeDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// This detection would need GPO audit policy data
	// For now, return informational finding
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Policy Change Audit Configuration Unknown",
		Description: "Unable to determine policy change audit configuration. Policy changes should be audited for security.",
		Count:       0,
		Details: map[string]interface{}{
			"recommendation": "Enable 'Audit Policy Change' for both Success and Failure.",
			"attacksUndetected": []string{
				"GPO poisoning",
				"Security policy weakening",
				"Audit policy tampering",
				"Firewall rule modifications",
			},
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAuditPolicyChangeDetector())
}
