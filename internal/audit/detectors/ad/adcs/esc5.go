package adcs

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ESC5Detector detects ESC5: PKI Object ACL Vulnerabilities
type ESC5Detector struct {
	audit.BaseDetector
}

// NewESC5Detector creates a new detector
func NewESC5Detector() *ESC5Detector {
	return &ESC5Detector{
		BaseDetector: audit.NewBaseDetector("ESC5_PKI_OBJECT_ACL", audit.CategoryADCS),
	}
}

// Detect executes the detection
func (d *ESC5Detector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// This would analyze ACLs on:
	// - CA computer object
	// - CN=Public Key Services,CN=Services,CN=Configuration
	// - CN=Enrollment Services,CN=Public Key Services,...
	// - CN=Certificate Templates,CN=Public Key Services,...

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "ESC5 - PKI Object ACL Review Required",
		Description: "PKI-related AD objects should be reviewed for overly permissive ACLs that could allow non-admins to modify CA configuration or templates.",
		Count:       0, // Placeholder until ACL analysis implemented
		Details: map[string]interface{}{
			"note": "Manual review of PKI object ACLs recommended.",
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewESC5Detector())
}
