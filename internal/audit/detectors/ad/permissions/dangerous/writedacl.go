package dangerous

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// WriteDACLDetector detects WriteDACL permission on sensitive objects
type WriteDACLDetector struct {
	audit.BaseDetector
}

// NewWriteDACLDetector creates a new detector
func NewWriteDACLDetector() *WriteDACLDetector {
	return &WriteDACLDetector{
		BaseDetector: audit.NewBaseDetector("ACL_WRITEDACL", audit.CategoryPermissions),
	}
}

// Detect executes the detection
func (d *WriteDACLDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	const writeDACL = 0x00040000

	var affected []types.ACLEntry

	for _, ace := range data.ACLEntries {
		if (ace.AccessMask & writeDACL) != 0 {
			affected = append(affected, ace)
		}
	}

	uniqueObjects := helpers.GetUniqueObjects(affected)
	totalInstances := len(affected)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "ACL WriteDACL",
		Description: "WriteDACL permission on sensitive AD objects. Can modify object's security descriptor to grant additional permissions.",
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
	audit.MustRegister(NewWriteDACLDetector())
}
