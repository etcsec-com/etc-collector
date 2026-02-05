package adcs

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ESC4Detector detects ESC4: Vulnerable Certificate Template ACL
type ESC4Detector struct {
	audit.BaseDetector
}

// NewESC4Detector creates a new detector
func NewESC4Detector() *ESC4Detector {
	return &ESC4Detector{
		BaseDetector: audit.NewBaseDetector("ESC4_VULNERABLE_TEMPLATE_ACL", audit.CategoryADCS),
	}
}

// Detect executes the detection
func (d *ESC4Detector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// In a full implementation, this would parse nTSecurityDescriptor and check for
	// GenericAll, GenericWrite, WriteDacl, WriteOwner, or WriteProperty rights
	// for non-admin principals

	// Count templates with authentication capability for review
	authTemplatesCount := 0
	for _, t := range data.CertTemplates {
		if HasAuthenticationEKU(t.ExtendedKeyUsage) {
			authTemplatesCount++
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "ESC4 - Certificate Template ACL Review Required",
		Description: "Certificate templates with authentication capability should be reviewed for overly permissive ACLs that allow non-admins to modify template properties.",
		Count:       0, // Set to 0 until actual ACL analysis is implemented
		Details: map[string]interface{}{
			"note":                "Full ACL analysis requires parsing nTSecurityDescriptor. Manual review recommended.",
			"templatesWithAuthEku": authTemplatesCount,
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewESC4Detector())
}
