package signing

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// SmbV1EnabledDetector detects if SMBv1 is enabled
type SmbV1EnabledDetector struct {
	audit.BaseDetector
}

// NewSmbV1EnabledDetector creates a new detector
func NewSmbV1EnabledDetector() *SmbV1EnabledDetector {
	return &SmbV1EnabledDetector{
		BaseDetector: audit.NewBaseDetector("SMB_V1_ENABLED", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *SmbV1EnabledDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// This requires GPO/registry settings - for now, flag for manual review
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "SMBv1 Configuration Unknown",
		Description: "Unable to determine SMBv1 configuration. Manual review recommended.",
		Count:       0,
		Details: map[string]interface{}{
			"note":           "GPO/Registry settings not available via LDAP. Check SMB1 registry values and Windows features manually.",
			"recommendation": "Disable SMBv1 on all systems. Use SMBv2/v3 instead.",
			"vulnerabilities": []string{
				"EternalBlue (MS17-010)",
				"WannaCry ransomware",
				"NotPetya malware",
			},
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSmbV1EnabledDetector())
}
