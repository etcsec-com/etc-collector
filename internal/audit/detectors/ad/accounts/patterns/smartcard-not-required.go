package patterns

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// SmartcardNotRequiredDetector detects accounts without smartcard requirement
type SmartcardNotRequiredDetector struct {
	audit.BaseDetector
}

// NewSmartcardNotRequiredDetector creates a new detector
func NewSmartcardNotRequiredDetector() *SmartcardNotRequiredDetector {
	return &SmartcardNotRequiredDetector{
		BaseDetector: audit.NewBaseDetector("SMARTCARD_NOT_REQUIRED", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *SmartcardNotRequiredDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	// UAC flag 0x40000 = SMARTCARD_REQUIRED
	const smartcardRequiredFlag = 0x40000

	for _, u := range data.Users {
		// Only check enabled privileged accounts
		if u.Disabled {
			continue
		}
		if !u.AdminCount {
			continue
		}

		// Check if SMARTCARD_REQUIRED is NOT set
		if (u.UserAccountControl & smartcardRequiredFlag) == 0 {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Smartcard Not Required",
		Description: "Privileged accounts (adminCount=1) without smartcard requirement. High-value accounts should require strong authentication.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSmartcardNotRequiredDetector())
}
