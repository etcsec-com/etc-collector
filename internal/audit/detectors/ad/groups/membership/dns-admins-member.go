package membership

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func toAffectedMemberEntities(members []string) []types.AffectedEntity {
	entities := make([]types.AffectedEntity, len(members))
	for i, m := range members {
		entities[i] = types.AffectedEntity{
			Type:           "member",
			SAMAccountName: m,
		}
	}
	return entities
}

// DnsAdminsMemberDetector checks for DnsAdmins membership
type DnsAdminsMemberDetector struct {
	audit.BaseDetector
}

// NewDnsAdminsMemberDetector creates a new detector
func NewDnsAdminsMemberDetector() *DnsAdminsMemberDetector {
	return &DnsAdminsMemberDetector{
		BaseDetector: audit.NewBaseDetector("DNS_ADMINS_MEMBER", audit.CategoryGroups),
	}
}

// Detect executes the detection
func (d *DnsAdminsMemberDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []string

	for _, user := range data.Users {
		for _, groupDN := range user.MemberOf {
			if strings.Contains(groupDN, "CN=DnsAdmins") {
				affected = append(affected, user.SAMAccountName)
				break
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "DnsAdmins Member",
		Description: "Users in DnsAdmins group. Can load arbitrary DLLs on domain controllers (escalation to Domain Admin).",
		Count:       len(affected),
	}

	if len(affected) > 0 {
		finding.AffectedEntities = toAffectedMemberEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDnsAdminsMemberDetector())
}
