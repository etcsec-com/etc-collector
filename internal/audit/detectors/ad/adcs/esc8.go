package adcs

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ESC8Detector detects ESC8: NTLM Relay to AD CS HTTP Endpoint
type ESC8Detector struct {
	audit.BaseDetector
}

// NewESC8Detector creates a new detector
func NewESC8Detector() *ESC8Detector {
	return &ESC8Detector{
		BaseDetector: audit.NewBaseDetector("ESC8_HTTP_ENROLLMENT", audit.CategoryADCS),
	}
}

// Detect executes the detection
func (d *ESC8Detector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// HTTP enrollment endpoints are typically at:
	// http://<CA>/certsrv/
	// Cannot detect via LDAP alone - would need network connectivity check

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "ESC8 - Web Enrollment Check Required",
		Description: "Certificate Authorities should be checked for HTTP-based web enrollment endpoints which are vulnerable to NTLM relay attacks.",
		Count:       0, // Cannot detect via LDAP
		Details: map[string]interface{}{
			"note": "Check for http://<CA>/certsrv/ endpoints. HTTPS with Extended Protection mitigates this.",
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewESC8Detector())
}
