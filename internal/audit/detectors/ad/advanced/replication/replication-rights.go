package replication

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ReplicationRightsDetector detects accounts with potential replication rights
type ReplicationRightsDetector struct {
	audit.BaseDetector
}

// NewReplicationRightsDetector creates a new detector
func NewReplicationRightsDetector() *ReplicationRightsDetector {
	return &ReplicationRightsDetector{
		BaseDetector: audit.NewBaseDetector("REPLICATION_RIGHTS", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *ReplicationRightsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		// adminCount=1 but not in standard admin groups
		if !u.AdminCount {
			continue
		}

		if len(u.MemberOf) == 0 {
			// Has adminCount but no groups
			affected = append(affected, u)
			continue
		}

		isInStandardAdminGroups := false
		for _, dn := range u.MemberOf {
			dnLower := strings.ToLower(dn)
			if strings.Contains(dnLower, "cn=domain admins") ||
				strings.Contains(dnLower, "cn=enterprise admins") ||
				strings.Contains(dnLower, "cn=administrators") {
				isInStandardAdminGroups = true
				break
			}
		}

		if !isInStandardAdminGroups {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Replication Rights",
		Description: "Account with adminCount=1 outside standard admin groups. May have replication rights (DCSync).",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewReplicationRightsDetector())
}
