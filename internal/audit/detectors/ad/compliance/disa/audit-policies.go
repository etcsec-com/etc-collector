package disa

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AuditPoliciesDetector checks DISA STIG audit policy compliance
type AuditPoliciesDetector struct {
	audit.BaseDetector
}

// NewAuditPoliciesDetector creates a new detector
func NewAuditPoliciesDetector() *AuditPoliciesDetector {
	return &AuditPoliciesDetector{
		BaseDetector: audit.NewBaseDetector("DISA_AUDIT_POLICIES", audit.CategoryCompliance),
	}
}

// Detect executes the detection
func (d *AuditPoliciesDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// DISA STIG audit policy requirements cannot be fully verified via LDAP
	// These settings are typically in GPOs and require additional tools to audit

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "DISA STIG Audit Policies Review Required",
		Description: "DISA STIG audit policy compliance cannot be verified via LDAP. Manual review of audit policies recommended.",
		Count:       0,
		Details: map[string]interface{}{
			"framework": "DISA",
			"stig":      "Windows Server STIG",
			"note":      "Audit policy settings require GPO analysis",
			"requiredAuditCategories": []string{
				"V-63447: Account Logon - Credential Validation",
				"V-63449: Account Management - Security Group Management",
				"V-63451: Account Management - User Account Management",
				"V-63453: Detailed Tracking - Process Creation",
				"V-63455: Logon/Logoff - Logon",
				"V-63457: Logon/Logoff - Special Logon",
				"V-63459: Object Access - Removable Storage",
				"V-63461: Policy Change - Audit Policy Change",
				"V-63463: Privilege Use - Sensitive Privilege Use",
				"V-63465: System - Security State Change",
				"V-63467: System - Security System Extension",
			},
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAuditPoliciesDetector())
}
