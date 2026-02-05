package high

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AsrepToAdminDetector detects AS-REP roastable users with path to admin groups
type AsrepToAdminDetector struct {
	audit.BaseDetector
}

// NewAsrepToAdminDetector creates a new detector
func NewAsrepToAdminDetector() *AsrepToAdminDetector {
	return &AsrepToAdminDetector{
		BaseDetector: audit.NewBaseDetector("PATH_ASREP_TO_ADMIN", audit.CategoryAttackPaths),
	}
}

// UAC flag for DONT_REQUIRE_PREAUTH
const uacDontRequirePreauth = 0x400000

// Detect executes the detection
func (d *AsrepToAdminDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		// Find AS-REP roastable users (DONT_REQUIRE_PREAUTH flag)
		hasNoPreauth := (u.UserAccountControl & uacDontRequirePreauth) != 0
		if !hasNoPreauth || !u.Enabled() {
			continue
		}

		// Check if member of privileged groups
		isPrivileged := false
		for _, memberOf := range u.MemberOf {
			memberOfLower := strings.ToLower(memberOf)
			if strings.Contains(memberOfLower, "domain admins") ||
				strings.Contains(memberOfLower, "enterprise admins") ||
				strings.Contains(memberOfLower, "administrators") ||
				strings.Contains(memberOfLower, "account operators") ||
				strings.Contains(memberOfLower, "backup operators") {
				isPrivileged = true
				break
			}
		}

		if isPrivileged {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "AS-REP Roasting Path to Admin",
		Description: "User without Kerberos pre-authentication is member of admin group. AS-REP roasting can lead to admin compromise.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
		finding.Details = map[string]interface{}{
			"attackVector": "Request AS-REP → Offline crack → Admin access",
			"mitigation":   "Enable Kerberos pre-authentication, remove from admin groups",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAsrepToAdminDetector())
}
