package gpo

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// OrphanedDetector checks for orphaned GPOs
type OrphanedDetector struct {
	audit.BaseDetector
}

// NewOrphanedDetector creates a new detector
func NewOrphanedDetector() *OrphanedDetector {
	return &OrphanedDetector{
		BaseDetector: audit.NewBaseDetector("GPO_ORPHANED", audit.CategoryGPO),
	}
}

// Detect executes the detection
func (d *OrphanedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []string

	for _, gpo := range data.GPOs {
		// Check for GPOs with potential orphan indicators
		hasSysvolPath := gpo.FilePath != ""
		hasName := gpo.DisplayName != "" || gpo.CN != ""

		if !hasSysvolPath || !hasName {
			name := gpo.DisplayName
			if name == "" {
				name = gpo.CN
			}
			if name == "" {
				name = gpo.DistinguishedName
			}
			affected = append(affected, name)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Potentially Orphaned GPOs",
		Description: "GPOs that may be orphaned (missing SYSVOL content or AD object). Orphaned GPOs can cause processing errors and may indicate tampering.",
		Count:       len(affected),
		Details: map[string]interface{}{
			"recommendation": "Compare AD GPOs with SYSVOL folders. Use gpotool.exe or Get-GPO to identify orphans. Delete orphaned GPOs after verification.",
		},
	}

	if len(affected) > 0 {
		finding.AffectedEntities = toAffectedGPOEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewOrphanedDetector())
}
