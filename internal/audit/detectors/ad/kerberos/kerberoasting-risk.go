package kerberos

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// KerberoastingRiskDetector checks for user accounts with SPNs
type KerberoastingRiskDetector struct {
	audit.BaseDetector
}

// NewKerberoastingRiskDetector creates a new detector
func NewKerberoastingRiskDetector() *KerberoastingRiskDetector {
	return &KerberoastingRiskDetector{
		BaseDetector: audit.NewBaseDetector("KERBEROASTING_RISK", audit.CategoryKerberos),
	}
}

// Detect executes the detection
func (d *KerberoastingRiskDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []string

	for _, user := range data.Users {
		if len(user.ServicePrincipalNames) > 0 {
			affected = append(affected, user.SAMAccountName)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Kerberoasting Risk",
		Description: "User accounts with Service Principal Names (SPNs). Vulnerable to Kerberoasting attacks to crack service account passwords.",
		Count:       len(affected),
	}

	if len(affected) > 0 {
		finding.AffectedEntities = toAffectedUserNameEntitiesKerberoasting(affected)
	}

	return []types.Finding{finding}
}

// toAffectedUserNameEntitiesKerberoasting converts a list of usernames to affected entities
func toAffectedUserNameEntitiesKerberoasting(names []string) []types.AffectedEntity {
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
	audit.MustRegister(NewKerberoastingRiskDetector())
}
