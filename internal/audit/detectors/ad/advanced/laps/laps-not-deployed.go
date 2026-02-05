package laps

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// LapsNotDeployedDetector detects computers without LAPS
type LapsNotDeployedDetector struct {
	audit.BaseDetector
}

// NewLapsNotDeployedDetector creates a new detector
func NewLapsNotDeployedDetector() *LapsNotDeployedDetector {
	return &LapsNotDeployedDetector{
		BaseDetector: audit.NewBaseDetector("LAPS_NOT_DEPLOYED", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *LapsNotDeployedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		// No LAPS (neither legacy nor Windows LAPS)
		if c.LegacyLAPSPassword == "" && c.WindowsLAPSPassword == "" {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "LAPS Not Deployed",
		Description: "LAPS not deployed on domain computers. Shared/static local admin passwords across workstations.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewLapsNotDeployedDetector())
}
