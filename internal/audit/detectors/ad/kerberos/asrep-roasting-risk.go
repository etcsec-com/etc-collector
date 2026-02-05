package kerberos

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AsrepRoastingRiskDetector checks for accounts without Kerberos pre-authentication
type AsrepRoastingRiskDetector struct {
	audit.BaseDetector
}

// NewAsrepRoastingRiskDetector creates a new detector
func NewAsrepRoastingRiskDetector() *AsrepRoastingRiskDetector {
	return &AsrepRoastingRiskDetector{
		BaseDetector: audit.NewBaseDetector("ASREP_ROASTING_RISK", audit.CategoryKerberos),
	}
}

// Detect executes the detection
func (d *AsrepRoastingRiskDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []string

	for _, user := range data.Users {
		// Check for DONT_REQ_PREAUTH flag (0x400000)
		if (user.UserAccountControl & uacDontReqPreauth) != 0 {
			affected = append(affected, user.SAMAccountName)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "AS-REP Roasting Risk",
		Description: "User accounts without Kerberos pre-authentication required (UAC 0x400000). Vulnerable to AS-REP roasting attacks.",
		Count:       len(affected),
	}

	if len(affected) > 0 {
		finding.AffectedEntities = toAffectedUserNameEntitiesAsrep(affected)
	}

	return []types.Finding{finding}
}

// toAffectedUserNameEntitiesAsrep converts a list of usernames to affected entities
func toAffectedUserNameEntitiesAsrep(names []string) []types.AffectedEntity {
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
	audit.MustRegister(NewAsrepRoastingRiskDetector())
}
