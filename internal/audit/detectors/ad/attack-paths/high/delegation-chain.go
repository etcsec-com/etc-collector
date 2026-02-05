package high

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DelegationChainDetector detects delegation chains to privileged targets
type DelegationChainDetector struct {
	audit.BaseDetector
}

// NewDelegationChainDetector creates a new detector
func NewDelegationChainDetector() *DelegationChainDetector {
	return &DelegationChainDetector{
		BaseDetector: audit.NewBaseDetector("PATH_DELEGATION_CHAIN", audit.CategoryAttackPaths),
	}
}

var dcServicePatterns = []string{"ldap/", "cifs/", "host/", "krbtgt/"}

// Detect executes the detection
func (d *DelegationChainDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var usersWithDelegation []types.User
	var computersWithDelegation []types.Computer
	var affectedUsers []types.User

	for _, u := range data.Users {
		if len(u.AllowedToDelegateTo) == 0 {
			continue
		}
		usersWithDelegation = append(usersWithDelegation, u)

		// Check if delegation targets include privileged services
		hasDCTarget := false
		for _, target := range u.AllowedToDelegateTo {
			targetLower := strings.ToLower(target)
			for _, pattern := range dcServicePatterns {
				if strings.HasPrefix(targetLower, strings.ToLower(pattern)) {
					hasDCTarget = true
					break
				}
			}
			if hasDCTarget {
				break
			}
		}

		if hasDCTarget {
			affectedUsers = append(affectedUsers, u)
		}
	}

	for _, c := range data.Computers {
		if len(c.AllowedToDelegateTo) > 0 {
			computersWithDelegation = append(computersWithDelegation, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Delegation Chain to Privileged Target",
		Description: "Accounts with constrained delegation to domain controller services. Can be exploited to impersonate privileged users.",
		Count:       len(affectedUsers) + len(computersWithDelegation),
		Details: map[string]interface{}{
			"usersWithDelegation":     len(usersWithDelegation),
			"computersWithDelegation": len(computersWithDelegation),
			"attackVector":            "Request S4U2Self → S4U2Proxy to DC service → Impersonate DA",
			"mitigation":              "Remove unnecessary delegation, use Protected Users group",
		},
	}

	if data.IncludeDetails && len(affectedUsers) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affectedUsers)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDelegationChainDetector())
}
