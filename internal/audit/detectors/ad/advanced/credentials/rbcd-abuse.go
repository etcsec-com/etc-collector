package credentials

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// RBCDAbuseDetector detects RBCD abuse configurations
type RBCDAbuseDetector struct {
	audit.BaseDetector
}

// NewRBCDAbuseDetector creates a new detector
func NewRBCDAbuseDetector() *RBCDAbuseDetector {
	return &RBCDAbuseDetector{
		BaseDetector: audit.NewBaseDetector("RBCD_ABUSE", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *RBCDAbuseDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		// Check msDS-AllowedToActOnBehalfOfOtherIdentity attribute
		if len(u.AllowedToActOnBehalfOfOtherIdentity) > 0 {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "RBCD Abuse",
		Description: "msDS-AllowedToActOnBehalfOfOtherIdentity configured. Enables privilege escalation via resource-based delegation.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewRBCDAbuseDetector())
}
