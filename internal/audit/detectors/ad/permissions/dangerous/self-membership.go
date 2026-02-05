package dangerous

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// SelfMembershipDetector detects self-membership rights on groups
type SelfMembershipDetector struct {
	audit.BaseDetector
}

// NewSelfMembershipDetector creates a new detector
func NewSelfMembershipDetector() *SelfMembershipDetector {
	return &SelfMembershipDetector{
		BaseDetector: audit.NewBaseDetector("ACL_SELF_MEMBERSHIP", audit.CategoryPermissions),
	}
}

// Detect executes the detection
func (d *SelfMembershipDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Self-membership GUID: bf9679c0-0de6-11d0-a285-00aa003049e2
	const selfMembershipGUID = "bf9679c0-0de6-11d0-a285-00aa003049e2"
	const writeSelf = 0x8 // ADS_RIGHT_DS_SELF

	var affected []types.ACLEntry

	for _, ace := range data.ACLEntries {
		hasWriteSelf := (ace.AccessMask & writeSelf) != 0
		isSelfMembership := strings.ToLower(ace.ObjectType) == selfMembershipGUID ||
			strings.Contains(strings.ToLower(ace.ObjectType), "member")

		if hasWriteSelf || isSelfMembership {
			affected = append(affected, ace)
		}
	}

	uniqueObjects := helpers.GetUniqueObjects(affected)
	totalInstances := len(affected)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Self-Membership Rights",
		Description: "Principals with self-membership rights on groups. Allows adding oneself to a group, potentially gaining elevated privileges.",
		Count:       len(uniqueObjects),
	}

	if totalInstances != len(uniqueObjects) {
		finding.TotalInstances = totalInstances
	}

	if data.IncludeDetails && len(uniqueObjects) > 0 {
		entities := make([]types.AffectedEntity, len(uniqueObjects))
		for i, dn := range uniqueObjects {
			entities[i] = types.AffectedEntity{
				Type: "group",
				DN:   dn,
			}
		}
		finding.AffectedEntities = entities
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSelfMembershipDetector())
}
