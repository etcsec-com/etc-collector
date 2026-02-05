package monitoring

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AuditLogonEventsDetector checks if logon events are audited
type AuditLogonEventsDetector struct {
	audit.BaseDetector
}

// NewAuditLogonEventsDetector creates a new detector
func NewAuditLogonEventsDetector() *AuditLogonEventsDetector {
	return &AuditLogonEventsDetector{
		BaseDetector: audit.NewBaseDetector("AUDIT_LOGON_EVENTS_DISABLED", audit.CategoryMonitoring),
	}
}

// Detect executes the detection
func (d *AuditLogonEventsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// This detection would need GPO audit policy data
	// For now, return informational finding
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Logon Audit Configuration Unknown",
		Description: "Unable to determine logon audit configuration. Manual review recommended.",
		Count:       0,
		Details: map[string]interface{}{
			"note":               "GPO audit settings not available. Check Advanced Audit Policy Configuration manually.",
			"recommendation":     "Enable 'Audit Logon Events' and 'Audit Account Logon Events' for both Success and Failure.",
			"missingCategories":  []string{"Account Logon", "Logon/Logoff", "Logon"},
			"attacksUndetected": []string{
				"Brute force attacks",
				"Password spraying",
				"Pass-the-hash",
				"Kerberos ticket attacks",
			},
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAuditLogonEventsDetector())
}
