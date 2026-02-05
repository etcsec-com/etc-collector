package kerberos

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ConstrainedDelegationDetector checks for accounts with constrained Kerberos delegation
type ConstrainedDelegationDetector struct {
	audit.BaseDetector
}

// NewConstrainedDelegationDetector creates a new detector
func NewConstrainedDelegationDetector() *ConstrainedDelegationDetector {
	return &ConstrainedDelegationDetector{
		BaseDetector: audit.NewBaseDetector("CONSTRAINED_DELEGATION", audit.CategoryKerberos),
	}
}

const uacTrustedToAuthForDelegation = 0x1000000

// Detect executes the detection
func (d *ConstrainedDelegationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []string

	for _, user := range data.Users {
		// Check for TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION flag (0x1000000)
		if (user.UserAccountControl & uacTrustedToAuthForDelegation) != 0 {
			affected = append(affected, user.SAMAccountName)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Constrained Delegation",
		Description: "User accounts with constrained Kerberos delegation configured (UAC 0x1000000). Can impersonate users to specific services.",
		Count:       len(affected),
	}

	if len(affected) > 0 {
		finding.AffectedEntities = toAffectedUserNameEntitiesConstrained(affected)
	}

	return []types.Finding{finding}
}

// toAffectedUserNameEntitiesConstrained converts a list of usernames to affected entities
func toAffectedUserNameEntitiesConstrained(names []string) []types.AffectedEntity {
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
	audit.MustRegister(NewConstrainedDelegationDetector())
}
