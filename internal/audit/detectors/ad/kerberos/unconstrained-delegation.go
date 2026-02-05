package kerberos

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// UnconstrainedDelegationDetector checks for accounts with unconstrained Kerberos delegation
type UnconstrainedDelegationDetector struct {
	audit.BaseDetector
}

// NewUnconstrainedDelegationDetector creates a new detector
func NewUnconstrainedDelegationDetector() *UnconstrainedDelegationDetector {
	return &UnconstrainedDelegationDetector{
		BaseDetector: audit.NewBaseDetector("UNCONSTRAINED_DELEGATION", audit.CategoryKerberos),
	}
}

const uacTrustedForDelegation = 0x80000

// Detect executes the detection
func (d *UnconstrainedDelegationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []string

	for _, user := range data.Users {
		// Check for TRUSTED_FOR_DELEGATION flag (0x80000)
		if (user.UserAccountControl & uacTrustedForDelegation) != 0 {
			affected = append(affected, user.SAMAccountName)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Unconstrained Delegation",
		Description: "User accounts with unconstrained Kerberos delegation enabled (UAC 0x80000). Can impersonate any user.",
		Count:       len(affected),
	}

	if len(affected) > 0 {
		finding.AffectedEntities = toAffectedUserNameEntitiesUnconstrained(affected)
	}

	return []types.Finding{finding}
}

// toAffectedUserNameEntitiesUnconstrained converts a list of usernames to affected entities
func toAffectedUserNameEntitiesUnconstrained(names []string) []types.AffectedEntity {
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
	audit.MustRegister(NewUnconstrainedDelegationDetector())
}
