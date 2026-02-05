package adcs

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ESC7Detector detects ESC7: Vulnerable CA ACL
type ESC7Detector struct {
	audit.BaseDetector
}

// NewESC7Detector creates a new detector
func NewESC7Detector() *ESC7Detector {
	return &ESC7Detector{
		BaseDetector: audit.NewBaseDetector("ESC7_CA_VULNERABLE_ACL", audit.CategoryADCS),
	}
}

// Detect executes the detection
func (d *ESC7Detector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Would analyze nTSecurityDescriptor on CA enrollment objects for:
	// - ManageCA right
	// - ManageCertificates right
	// granted to non-admin principals

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "ESC7 - CA ACL Review Required",
		Description: "Certificate Authority ACLs should be reviewed for ManageCA or ManageCertificates rights granted to non-administrators.",
		Count:       0, // Placeholder until ACL analysis implemented
		Details: map[string]interface{}{
			"note": "Manual review of CA ACLs recommended.",
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewESC7Detector())
}
