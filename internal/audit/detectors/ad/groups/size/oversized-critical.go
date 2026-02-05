package size

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// OversizedCriticalDetector checks for groups with 500+ members
type OversizedCriticalDetector struct {
	audit.BaseDetector
}

// NewOversizedCriticalDetector creates a new detector
func NewOversizedCriticalDetector() *OversizedCriticalDetector {
	return &OversizedCriticalDetector{
		BaseDetector: audit.NewBaseDetector("OVERSIZED_GROUP_CRITICAL", audit.CategoryGroups),
	}
}

// Detect executes the detection
func (d *OversizedCriticalDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []string

	for _, group := range data.Groups {
		if len(group.Member) > 500 {
			name := group.SAMAccountName
			if name == "" {
				name = group.DistinguishedName
			}
			affected = append(affected, name)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Oversized Group (Critical)",
		Description: "Groups with 500+ members. Management/audit difficulty, excessive privileges, performance issues.",
		Count:       len(affected),
	}

	if len(affected) > 0 {
		finding.AffectedEntities = toAffectedGroupEntities(affected)
	}

	return []types.Finding{finding}
}

func toAffectedGroupEntities(names []string) []types.AffectedEntity {
	entities := make([]types.AffectedEntity, len(names))
	for i, name := range names {
		entities[i] = types.AffectedEntity{
			Type: "group",
			Name: name,
		}
	}
	return entities
}

func init() {
	audit.MustRegister(NewOversizedCriticalDetector())
}
