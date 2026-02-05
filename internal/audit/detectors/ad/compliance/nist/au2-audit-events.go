package nist

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AU2AuditEventsDetector checks NIST AU-2 audit events compliance
type AU2AuditEventsDetector struct {
	audit.BaseDetector
}

// NewAU2AuditEventsDetector creates a new detector
func NewAU2AuditEventsDetector() *AU2AuditEventsDetector {
	return &AU2AuditEventsDetector{
		BaseDetector: audit.NewBaseDetector("NIST_AU_2_AUDIT_EVENTS", audit.CategoryCompliance),
	}
}

// Detect executes the detection
func (d *AU2AuditEventsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// AU-2 audit event configuration cannot be fully verified via LDAP
	// This requires GPO audit policy analysis

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "NIST AU-2 Audit Events Review Required",
		Description: "NIST AU-2 audit event configuration cannot be fully verified via LDAP. Manual review of audit policies recommended.",
		Count:       0,
		Details: map[string]interface{}{
			"framework":   "NIST",
			"control":     "AU-2",
			"publication": "SP 800-53",
			"note":        "Audit policy settings require GPO analysis",
			"requiredEvents": []string{
				"AU-2(a): Account logon events",
				"AU-2(a): Account management",
				"AU-2(a): Directory service access",
				"AU-2(a): Logon events",
				"AU-2(a): Object access",
				"AU-2(a): Policy change",
				"AU-2(a): Privilege use",
				"AU-2(a): Process tracking",
				"AU-2(a): System events",
			},
			"recommendations": []string{
				"Enable Advanced Audit Policy Configuration",
				"Audit all security-relevant events",
				"Centralize log collection to SIEM",
				"Set appropriate log retention",
			},
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAU2AuditEventsDetector())
}
