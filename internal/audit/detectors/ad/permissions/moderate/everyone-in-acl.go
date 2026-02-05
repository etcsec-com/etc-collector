package moderate

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// EveryoneInACLDetector detects Everyone/Authenticated Users with write permissions
type EveryoneInACLDetector struct {
	audit.BaseDetector
}

// NewEveryoneInACLDetector creates a new detector
func NewEveryoneInACLDetector() *EveryoneInACLDetector {
	return &EveryoneInACLDetector{
		BaseDetector: audit.NewBaseDetector("EVERYONE_IN_ACL", audit.CategoryPermissions),
	}
}

// Detect executes the detection
func (d *EveryoneInACLDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	const everyoneSID = "S-1-1-0"
	const authenticatedUsersSID = "S-1-5-11"
	const writeMask = 0x00020000 // ADS_RIGHT_DS_WRITE_PROP

	var affected []types.ACLEntry

	for _, ace := range data.ACLEntries {
		isEveryone := ace.Trustee == everyoneSID || ace.Trustee == authenticatedUsersSID
		hasWrite := (ace.AccessMask & writeMask) != 0

		if isEveryone && hasWrite {
			affected = append(affected, ace)
		}
	}

	uniqueObjects := helpers.GetUniqueObjects(affected)
	totalInstances := len(affected)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Everyone in ACL",
		Description: "Everyone or Authenticated Users with write permissions in ACL. Overly permissive access.",
		Count:       len(uniqueObjects),
	}

	if totalInstances != len(uniqueObjects) {
		finding.TotalInstances = totalInstances
	}

	if data.IncludeDetails && len(uniqueObjects) > 0 {
		entities := make([]types.AffectedEntity, len(uniqueObjects))
		for i, dn := range uniqueObjects {
			entities[i] = types.AffectedEntity{
				Type: "object",
				DN:   dn,
			}
		}
		finding.AffectedEntities = entities
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewEveryoneInACLDetector())
}
