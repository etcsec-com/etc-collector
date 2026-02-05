package high

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NestedAdminDetector detects excessive group nesting leading to admin access
type NestedAdminDetector struct {
	audit.BaseDetector
}

// NewNestedAdminDetector creates a new detector
func NewNestedAdminDetector() *NestedAdminDetector {
	return &NestedAdminDetector{
		BaseDetector: audit.NewBaseDetector("PATH_NESTED_ADMIN", audit.CategoryAttackPaths),
	}
}

const excessiveDepth = 3

var privilegedGroups = []string{
	"domain admins",
	"enterprise admins",
	"administrators",
	"schema admins",
	"account operators",
	"backup operators",
	"server operators",
}

// Detect executes the detection
func (d *NestedAdminDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Build group membership map
	groupMemberOf := make(map[string][]string)
	for _, g := range data.Groups {
		groupMemberOf[strings.ToLower(g.DN)] = g.MemberOf
	}

	// Check for privileged groups
	privilegedGroupDNs := make(map[string]bool)
	for _, g := range data.Groups {
		for _, pg := range privilegedGroups {
			if strings.Contains(strings.ToLower(g.SAMAccountName), pg) {
				privilegedGroupDNs[strings.ToLower(g.DN)] = true
				break
			}
		}
	}

	var affected []types.User
	deepestNesting := 0

	for _, u := range data.Users {
		if len(u.MemberOf) == 0 {
			continue
		}

		// Check depth of each group membership
		for _, groupDN := range u.MemberOf {
			depth := calculateNestingDepth(strings.ToLower(groupDN), groupMemberOf, make(map[string]bool))

			if depth > excessiveDepth {
				// Check if path reaches privileged group
				if reachesPrivileged(strings.ToLower(groupDN), groupMemberOf, privilegedGroupDNs, make(map[string]bool)) {
					affected = append(affected, u)
					if depth > deepestNesting {
						deepestNesting = depth
					}
					break
				}
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Excessive Group Nesting to Admin",
		Description: "Users reach admin groups through excessive nesting (>3 levels). Makes privilege review difficult and may hide admin access.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
		finding.Details = map[string]interface{}{
			"threshold":      excessiveDepth,
			"deepestNesting": deepestNesting,
			"mitigation":     "Flatten group structure, limit nesting to 2-3 levels",
		}
	}

	return []types.Finding{finding}
}

func calculateNestingDepth(groupDN string, groupMemberOf map[string][]string, visited map[string]bool) int {
	if visited[groupDN] {
		return 0
	}
	visited[groupDN] = true

	parents := groupMemberOf[groupDN]
	if len(parents) == 0 {
		return 1
	}

	maxDepth := 0
	for _, parent := range parents {
		depth := calculateNestingDepth(strings.ToLower(parent), groupMemberOf, visited)
		if depth > maxDepth {
			maxDepth = depth
		}
	}

	return maxDepth + 1
}

func reachesPrivileged(groupDN string, groupMemberOf map[string][]string, privilegedDNs map[string]bool, visited map[string]bool) bool {
	if visited[groupDN] {
		return false
	}
	visited[groupDN] = true

	if privilegedDNs[groupDN] {
		return true
	}

	for _, parent := range groupMemberOf[groupDN] {
		if reachesPrivileged(strings.ToLower(parent), groupMemberOf, privilegedDNs, visited) {
			return true
		}
	}

	return false
}

func init() {
	audit.MustRegister(NewNestedAdminDetector())
}
