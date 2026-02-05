package critical

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AclToDADetector detects ACL-based privilege escalation paths to Domain Admin
type AclToDADetector struct {
	audit.BaseDetector
}

// NewAclToDADetector creates a new detector
func NewAclToDADetector() *AclToDADetector {
	return &AclToDADetector{
		BaseDetector: audit.NewBaseDetector("PATH_ACL_TO_DA", audit.CategoryAttackPaths),
	}
}

// Detect executes the detection
func (d *AclToDADetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// This detector would require graph analysis of ACL chains
	// For now, identify users with dangerous ACL rights

	var affected []types.User

	for _, u := range data.Users {
		if !u.Enabled() || u.AdminCount {
			continue
		}
		// Check if user has any write ACL rights to privileged objects
		if u.HasWriteDACL || u.HasGenericAll || u.HasWriteOwner {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "ACL-Based Privilege Escalation to Domain Admin",
		Description: "Non-privileged users can escalate to Domain Admin through ACL chain (WriteDACL, GenericAll, WriteOwner).",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
		finding.Details = map[string]interface{}{
			"attackVector": "Modify ACL → Take ownership → Add to DA group",
			"mitigation":   "Review and restrict dangerous ACL permissions",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAclToDADetector())
}
