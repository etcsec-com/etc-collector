package dangerous

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// WriteOwnerDetector detects WriteOwner permission on sensitive objects
type WriteOwnerDetector struct {
	audit.BaseDetector
}

// NewWriteOwnerDetector creates a new detector
func NewWriteOwnerDetector() *WriteOwnerDetector {
	return &WriteOwnerDetector{
		BaseDetector: audit.NewBaseDetector("ACL_WRITEOWNER", audit.CategoryPermissions),
	}
}

// Detect executes the detection
func (d *WriteOwnerDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	const writeOwner = 0x00080000

	var affected []types.ACLEntry

	for _, ace := range data.ACLEntries {
		if (ace.AccessMask & writeOwner) != 0 {
			affected = append(affected, ace)
		}
	}

	uniqueObjects := helpers.GetUniqueObjects(affected)
	totalInstances := len(affected)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "ACL WriteOwner",
		Description: "WriteOwner permission on sensitive AD objects. Can take ownership of object and modify permissions.",
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
	audit.MustRegister(NewWriteOwnerDetector())
}
