package monitoring

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// SecurityLogSizeDetector checks if security log size is sufficient
type SecurityLogSizeDetector struct {
	audit.BaseDetector
}

// NewSecurityLogSizeDetector creates a new detector
func NewSecurityLogSizeDetector() *SecurityLogSizeDetector {
	return &SecurityLogSizeDetector{
		BaseDetector: audit.NewBaseDetector("SECURITY_LOG_SIZE_SMALL", audit.CategoryMonitoring),
	}
}

const minimumLogSizeKB = 128 * 1024 // 128 MB minimum recommended

// Detect executes the detection
func (d *SecurityLogSizeDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// This detection would need GPO event log settings data
	// For now, return informational finding
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Security Log Size Configuration Unknown",
		Description: "Unable to determine security event log size configuration. Adequate log size is important for forensic investigation.",
		Count:       0,
		Details: map[string]interface{}{
			"note":              "GPO event log settings not available. Verify Security log maximum size manually.",
			"recommendedSizeMB": minimumLogSizeKB / 1024,
			"risks": []string{
				"Critical events may be lost due to log rotation",
				"Incident response hampered by missing events",
				"Compliance violations for log retention requirements",
			},
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSecurityLogSizeDetector())
}
