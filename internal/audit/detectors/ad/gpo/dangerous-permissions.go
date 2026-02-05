package gpo

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DangerousPermissionsDetector checks for GPOs with dangerous permissions
type DangerousPermissionsDetector struct {
	audit.BaseDetector
}

// NewDangerousPermissionsDetector creates a new detector
func NewDangerousPermissionsDetector() *DangerousPermissionsDetector {
	return &DangerousPermissionsDetector{
		BaseDetector: audit.NewBaseDetector("GPO_DANGEROUS_PERMISSIONS", audit.CategoryGPO),
	}
}

// Detect executes the detection
func (d *DangerousPermissionsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Would analyze nTSecurityDescriptor on GPO objects for:
	// - GenericAll, GenericWrite, WriteDacl, WriteOwner, WriteProperty
	// granted to non-admin principals (Domain Users, Authenticated Users, etc.)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "GPO Permissions Review Required",
		Description: "Group Policy Objects should be reviewed for overly permissive ACLs that allow non-administrators to modify GPO settings.",
		Count:       0, // Placeholder until ACL analysis implemented
		Details: map[string]interface{}{
			"note":          "Manual review of GPO ACLs recommended. Check for non-admin principals with write access.",
			"gposToReview":  len(data.GPOs),
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDangerousPermissionsDetector())
}
