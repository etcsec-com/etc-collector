package replication

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DcsyncCapableDetector detects accounts capable of DCSync
type DcsyncCapableDetector struct {
	audit.BaseDetector
}

// NewDcsyncCapableDetector creates a new detector
func NewDcsyncCapableDetector() *DcsyncCapableDetector {
	return &DcsyncCapableDetector{
		BaseDetector: audit.NewBaseDetector("DCSYNC_CAPABLE", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *DcsyncCapableDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		// Check if user has DCSync rights (populated by ACL analysis)
		if u.HasDCSyncRights {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "DCSync Capable",
		Description: "Account with DS-Replication-Get-Changes and DS-Replication-Get-Changes-All rights. Can extract all password hashes.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDcsyncCapableDetector())
}
