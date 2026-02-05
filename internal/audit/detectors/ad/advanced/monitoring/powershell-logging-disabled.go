package monitoring

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PowershellLoggingDisabledDetector detects if PowerShell logging is disabled
type PowershellLoggingDisabledDetector struct {
	audit.BaseDetector
}

// NewPowershellLoggingDisabledDetector creates a new detector
func NewPowershellLoggingDisabledDetector() *PowershellLoggingDisabledDetector {
	return &PowershellLoggingDisabledDetector{
		BaseDetector: audit.NewBaseDetector("POWERSHELL_LOGGING_DISABLED", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *PowershellLoggingDisabledDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// This would require GPO settings from SYSVOL - for now, flag for manual review
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "PowerShell Logging Configuration Unknown",
		Description: "Unable to determine PowerShell logging configuration. Manual review recommended.",
		Count:       0,
		Details: map[string]interface{}{
			"note":           "GPO/Registry settings not available via LDAP. Check PowerShell logging GPO settings manually.",
			"recommendation": "Enable 'Turn on PowerShell Script Block Logging' and 'Turn on Module Logging' via GPO.",
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPowershellLoggingDisabledDetector())
}
