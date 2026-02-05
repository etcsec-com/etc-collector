package password

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NeverExpiresDetector detects accounts with passwords that never expire
type NeverExpiresDetector struct {
	audit.BaseDetector
}

// NewNeverExpiresDetector creates a new detector
func NewNeverExpiresDetector() *NeverExpiresDetector {
	return &NeverExpiresDetector{
		BaseDetector: audit.NewBaseDetector("PASSWORD_NEVER_EXPIRES", audit.CategoryPassword),
	}
}

// Detect executes the detection
func (d *NeverExpiresDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// DONT_EXPIRE_PASSWD flag (UAC 0x10000)
	const uacDontExpirePasswd = 0x10000

	var affected []types.User

	for _, u := range data.Users {
		// Check UAC flag for DONT_EXPIRE_PASSWD
		if (u.UserAccountControl & uacDontExpirePasswd) != 0 {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Password Never Expires",
		Description: "User accounts with passwords set to never expire (UAC flag 0x10000). Old passwords increase breach risk.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNeverExpiresDetector())
}
