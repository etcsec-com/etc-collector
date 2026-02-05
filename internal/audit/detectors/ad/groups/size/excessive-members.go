package size

import (
	"context"
	"sort"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ExcessiveMembersDetector checks for groups with excessive direct members
type ExcessiveMembersDetector struct {
	audit.BaseDetector
}

// NewExcessiveMembersDetector creates a new detector
func NewExcessiveMembersDetector() *ExcessiveMembersDetector {
	return &ExcessiveMembersDetector{
		BaseDetector: audit.NewBaseDetector("GROUP_EXCESSIVE_MEMBERS", audit.CategoryGroups),
	}
}

const excessiveThreshold = 100

// Detect executes the detection
func (d *ExcessiveMembersDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	type groupInfo struct {
		name        string
		memberCount int
	}

	var affected []groupInfo

	for _, group := range data.Groups {
		memberCount := len(group.Member)
		if memberCount > excessiveThreshold {
			name := group.SAMAccountName
			if name == "" {
				name = group.DistinguishedName
			}
			affected = append(affected, groupInfo{name: name, memberCount: memberCount})
		}
	}

	// Sort by member count (most members first)
	sort.Slice(affected, func(i, j int) bool {
		return affected[i].memberCount > affected[j].memberCount
	})

	var affectedNames []string
	for _, g := range affected {
		affectedNames = append(affectedNames, g.name)
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Group with Excessive Members",
		Description: "Groups with more than 100 direct members. Large groups are difficult to audit and may grant unintended access.",
		Count:       len(affected),
	}

	if len(affected) > 0 {
		finding.AffectedEntities = toAffectedGroupEntities(affectedNames)

		// Build largest groups list (max 5)
		largestGroups := make([]map[string]interface{}, 0, 5)
		for i := 0; i < len(affected) && i < 5; i++ {
			largestGroups = append(largestGroups, map[string]interface{}{
				"name":        affected[i].name,
				"memberCount": affected[i].memberCount,
			})
		}

		finding.Details = map[string]interface{}{
			"threshold":      excessiveThreshold,
			"largestGroups":  largestGroups,
			"recommendation": "Review large groups and consider breaking into smaller, role-based groups for better access control.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewExcessiveMembersDetector())
}
