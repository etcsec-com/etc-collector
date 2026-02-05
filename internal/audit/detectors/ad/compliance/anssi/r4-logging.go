package anssi

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// R4LoggingDetector checks ANSSI R4 logging compliance
type R4LoggingDetector struct {
	audit.BaseDetector
}

// NewR4LoggingDetector creates a new detector
func NewR4LoggingDetector() *R4LoggingDetector {
	return &R4LoggingDetector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R4_LOGGING", audit.CategoryCompliance),
	}
}

// Detect executes the detection
func (d *R4LoggingDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// This would require GPO analysis for audit policy settings
	// For now, flag as requiring manual review

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "ANSSI R4 - Logging Configuration Unknown",
		Description: "Unable to verify logging configuration per ANSSI R4. Manual review of audit policies recommended.",
		Count:       0,
		Details: map[string]interface{}{
			"framework":      "ANSSI",
			"control":        "R4",
			"note":           "GPO audit policy settings not available via LDAP",
			"recommendation": "Enable Advanced Audit Policy for all critical categories",
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewR4LoggingDetector())
}
