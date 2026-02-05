package kerberos

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AdminAsrepRoastableDetector checks for privileged accounts without Kerberos pre-authentication
type AdminAsrepRoastableDetector struct {
	audit.BaseDetector
}

// NewAdminAsrepRoastableDetector creates a new detector
func NewAdminAsrepRoastableDetector() *AdminAsrepRoastableDetector {
	return &AdminAsrepRoastableDetector{
		BaseDetector: audit.NewBaseDetector("ADMIN_ASREP_ROASTABLE", audit.CategoryKerberos),
	}
}

var privilegedGroupsAsrep = []string{
	"Domain Admins",
	"Enterprise Admins",
	"Schema Admins",
	"Administrators",
	"Account Operators",
	"Backup Operators",
	"Server Operators",
}

const uacDontReqPreauth = 0x400000

// Detect executes the detection
func (d *AdminAsrepRoastableDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []string

	for _, user := range data.Users {
		// Check for DONT_REQ_PREAUTH flag
		if (user.UserAccountControl & uacDontReqPreauth) == 0 {
			continue
		}

		// Check if user is in a privileged group
		isPrivileged := false
		for _, groupDN := range user.MemberOf {
			groupDNUpper := strings.ToUpper(groupDN)
			for _, group := range privilegedGroupsAsrep {
				if strings.Contains(groupDNUpper, "CN="+strings.ToUpper(group)) {
					isPrivileged = true
					break
				}
			}
			if isPrivileged {
				break
			}
		}

		if isPrivileged {
			affected = append(affected, user.SAMAccountName)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Privileged Account AS-REP Roastable",
		Description: "Privileged accounts (Domain Admins, Enterprise Admins, etc.) without Kerberos pre-authentication. High-value targets for AS-REP roasting attacks - immediate domain compromise risk.",
		Count:       len(affected),
	}

	if len(affected) > 0 {
		finding.AffectedEntities = toAffectedUserNameEntitiesAdminAsrep(affected)
		finding.Details = map[string]interface{}{
			"risk":           "CRITICAL - Privileged account password hash can be obtained offline",
			"recommendation": "Enable Kerberos pre-authentication immediately for all privileged accounts",
		}
	}

	return []types.Finding{finding}
}

// toAffectedUserNameEntitiesAdminAsrep converts a list of usernames to affected entities
func toAffectedUserNameEntitiesAdminAsrep(names []string) []types.AffectedEntity {
	entities := make([]types.AffectedEntity, len(names))
	for i, name := range names {
		entities[i] = types.AffectedEntity{
			Type:           "user",
			SAMAccountName: name,
		}
	}
	return entities
}

func init() {
	audit.MustRegister(NewAdminAsrepRoastableDetector())
}
