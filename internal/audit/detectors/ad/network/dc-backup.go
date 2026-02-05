package network

import (
	"context"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DcBackupDetector checks for DCs with potentially old backups
type DcBackupDetector struct {
	audit.BaseDetector
}

// NewDcBackupDetector creates a new detector
func NewDcBackupDetector() *DcBackupDetector {
	return &DcBackupDetector{
		BaseDetector: audit.NewBaseDetector("DC_BACKUP_OLD", audit.CategoryNetwork),
	}
}

// Detect executes the detection
func (d *DcBackupDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	thirtyDaysAgo := time.Now().AddDate(0, 0, -30)

	var possiblyUnbackedUp []string
	for _, dc := range data.DomainControllers {
		// If DC hasn't replicated password recently, it might indicate backup issues
		if !dc.PasswordLastSet.IsZero() && dc.PasswordLastSet.Before(thirtyDaysAgo) {
			possiblyUnbackedUp = append(possiblyUnbackedUp, dc.SAMAccountName)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Domain Controller Backup Review",
		Description: "Domain controllers should be backed up regularly. Tombstone lifetime is 180 days - DCs offline longer than this cannot rejoin.",
		Count:       len(possiblyUnbackedUp),
		Details: map[string]interface{}{
			"recommendation": "Verify Windows Server Backup or third-party backup solution is configured on all DCs.",
		},
	}

	if len(possiblyUnbackedUp) > 0 {
		finding.AffectedEntities = toAffectedComputerNameEntitiesBackup(possiblyUnbackedUp)
	}

	return []types.Finding{finding}
}

// toAffectedComputerNameEntitiesBackup converts a list of computer names to affected entities
func toAffectedComputerNameEntitiesBackup(names []string) []types.AffectedEntity {
	entities := make([]types.AffectedEntity, len(names))
	for i, name := range names {
		entities[i] = types.AffectedEntity{
			Type:           "computer",
			SAMAccountName: name,
		}
	}
	return entities
}

func init() {
	audit.MustRegister(NewDcBackupDetector())
}
