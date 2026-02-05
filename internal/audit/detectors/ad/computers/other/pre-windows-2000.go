package other

import (
	"context"
	"regexp"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PreWindows2000Detector checks for pre-Windows 2000 computers
type PreWindows2000Detector struct {
	audit.BaseDetector
}

// NewPreWindows2000Detector creates a new detector
func NewPreWindows2000Detector() *PreWindows2000Detector {
	return &PreWindows2000Detector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_PRE_WINDOWS_2000", audit.CategoryComputers),
	}
}

var preWin2000Pattern = regexp.MustCompile(`(?i)Windows NT|Windows 2000|Windows 95|Windows 98`)

// Detect executes the detection
func (d *PreWindows2000Detector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		if c.OperatingSystem == "" {
			continue
		}
		if preWin2000Pattern.MatchString(c.OperatingSystem) {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Pre-Windows 2000 Computer",
		Description: "Pre-Windows 2000 compatible computer. Weak security settings, potential compatibility exploits.",
		Count:       len(affected),
	}

	if len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPreWindows2000Detector())
}
