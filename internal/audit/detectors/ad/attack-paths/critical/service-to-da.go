package critical

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ServiceToDADetector detects service accounts with path to Domain Admin
type ServiceToDADetector struct {
	audit.BaseDetector
}

// NewServiceToDADetector creates a new detector
func NewServiceToDADetector() *ServiceToDADetector {
	return &ServiceToDADetector{
		BaseDetector: audit.NewBaseDetector("PATH_SERVICE_TO_DA", audit.CategoryAttackPaths),
	}
}

// Detect executes the detection
func (d *ServiceToDADetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Service accounts = users with SPNs
	var serviceAccounts []types.User
	var affected []types.User

	for _, u := range data.Users {
		if !u.Enabled() || len(u.ServicePrincipalNames) == 0 {
			continue
		}
		serviceAccounts = append(serviceAccounts, u)

		// Check if service account has path to DA (via membership, ACL, or delegation)
		hasPathToDA := u.AdminCount ||
			u.HasDCSyncRights ||
			len(u.AllowedToDelegateTo) > 0 ||
			len(u.AllowedToActOnBehalfOfOtherIdentity) > 0

		if hasPathToDA {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Service Account Path to Domain Admin",
		Description: "Service accounts with paths to Domain Admin through membership, ACLs, or delegation. Compromising these accounts leads to DA.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
		finding.Details = map[string]interface{}{
			"totalServiceAccounts": len(serviceAccounts),
			"withPathToDA":         len(affected),
			"attackVector":         "Kerberoast/Credential theft → Exploit path → Domain Admin",
			"mitigation":           "Use gMSA, minimize service account privileges, regular password rotation",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewServiceToDADetector())
}
