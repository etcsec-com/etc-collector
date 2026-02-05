package monitoring

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AuditAccountMgmtDetector checks if account management events are audited
type AuditAccountMgmtDetector struct {
	audit.BaseDetector
}

// NewAuditAccountMgmtDetector creates a new detector
func NewAuditAccountMgmtDetector() *AuditAccountMgmtDetector {
	return &AuditAccountMgmtDetector{
		BaseDetector: audit.NewBaseDetector("AUDIT_ACCOUNT_MGMT_DISABLED", audit.CategoryMonitoring),
	}
}

// Detect executes the detection
func (d *AuditAccountMgmtDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// This detection would need GPO audit policy data
	// For now, return informational finding
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Account Management Audit Configuration Unknown",
		Description: "Unable to determine account management audit configuration. Account management events should be audited for security.",
		Count:       0,
		Details: map[string]interface{}{
			"recommendation": "Enable 'Audit Account Management' for both Success and Failure.",
			"attacksUndetected": []string{
				"Unauthorized account creation",
				"Privilege escalation via group membership",
				"Backdoor accounts",
				"Account takeover",
			},
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAuditAccountMgmtDetector())
}
