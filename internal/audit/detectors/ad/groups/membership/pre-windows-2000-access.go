package membership

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PreWindows2000AccessDetector checks for Pre-Windows 2000 Compatible Access membership
type PreWindows2000AccessDetector struct {
	audit.BaseDetector
}

// NewPreWindows2000AccessDetector creates a new detector
func NewPreWindows2000AccessDetector() *PreWindows2000AccessDetector {
	return &PreWindows2000AccessDetector{
		BaseDetector: audit.NewBaseDetector("PRE_WINDOWS_2000_ACCESS", audit.CategoryGroups),
	}
}

// Detect executes the detection
func (d *PreWindows2000AccessDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []string

	for _, user := range data.Users {
		for _, groupDN := range user.MemberOf {
			if strings.Contains(groupDN, "CN=Pre-Windows 2000 Compatible Access") {
				affected = append(affected, user.SAMAccountName)
				break
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Pre-Windows 2000 Compatible Access",
		Description: "Pre-Windows 2000 Compatible Access group has members. Overly permissive read access to AD objects.",
		Count:       len(affected),
	}

	if len(affected) > 0 {
		finding.AffectedEntities = toAffectedMemberEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPreWindows2000AccessDetector())
}
