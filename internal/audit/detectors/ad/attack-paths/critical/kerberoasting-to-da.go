package critical

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// KerberoastingToDADetector detects kerberoastable users with path to Domain Admin
type KerberoastingToDADetector struct {
	audit.BaseDetector
}

// NewKerberoastingToDADetector creates a new detector
func NewKerberoastingToDADetector() *KerberoastingToDADetector {
	return &KerberoastingToDADetector{
		BaseDetector: audit.NewBaseDetector("PATH_KERBEROASTING_TO_DA", audit.CategoryAttackPaths),
	}
}

// Detect executes the detection
func (d *KerberoastingToDADetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		// Find kerberoastable users (have SPN and are enabled)
		if !u.Enabled() || len(u.ServicePrincipalNames) == 0 {
			continue
		}

		// Check if user is member of privileged groups
		isPrivileged := false
		for _, memberOf := range u.MemberOf {
			memberOfLower := strings.ToLower(memberOf)
			if strings.Contains(memberOfLower, "domain admins") ||
				strings.Contains(memberOfLower, "enterprise admins") ||
				strings.Contains(memberOfLower, "administrators") {
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
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Kerberoasting Path to Domain Admin",
		Description: "User with SPN is member of privileged group. Kerberoasting this account and cracking the password leads to Domain Admin compromise.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
		finding.Details = map[string]interface{}{
			"attackVector": "Request TGS ticket → Offline crack → Domain Admin access",
			"mitigation":   "Use gMSA for service accounts, remove from privileged groups, use long complex passwords",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewKerberoastingToDADetector())
}
