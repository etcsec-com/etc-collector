package advanced

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PrivilegedAccountSpnDetector detects privileged accounts with SPNs
type PrivilegedAccountSpnDetector struct {
	audit.BaseDetector
}

// NewPrivilegedAccountSpnDetector creates a new detector
func NewPrivilegedAccountSpnDetector() *PrivilegedAccountSpnDetector {
	return &PrivilegedAccountSpnDetector{
		BaseDetector: audit.NewBaseDetector("PRIVILEGED_ACCOUNT_SPN", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *PrivilegedAccountSpnDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		// Must be privileged (adminCount=true)
		if !u.AdminCount {
			continue
		}
		// Must be enabled
		if u.Disabled {
			continue
		}

		// Must have SPN
		if len(u.ServicePrincipalNames) > 0 {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Privileged Account with SPN",
		Description: "Privileged accounts (adminCount=1) have Service Principal Names configured. These accounts are vulnerable to Kerberoasting attacks.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
		finding.Details = map[string]interface{}{
			"attackVector":    "Request TGS ticket -> Offline crack password -> Full admin access",
			"recommendation":  "Remove SPNs from admin accounts. Use dedicated service accounts (preferably gMSA) for services.",
			"criticalRisk":    "Compromising these accounts grants immediate Domain Admin or equivalent access.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPrivilegedAccountSpnDetector())
}
