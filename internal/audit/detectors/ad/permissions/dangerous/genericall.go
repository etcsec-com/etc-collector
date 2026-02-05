package dangerous

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// GenericAllDetector detects GenericAll permission on sensitive objects
type GenericAllDetector struct {
	audit.BaseDetector
}

// NewGenericAllDetector creates a new detector
func NewGenericAllDetector() *GenericAllDetector {
	return &GenericAllDetector{
		BaseDetector: audit.NewBaseDetector("ACL_GENERICALL", audit.CategoryPermissions),
	}
}

// Detect executes the detection
func (d *GenericAllDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// GENERIC_ALL raw value
	const genericAll = 0x10000000
	// Full control mask for AD objects (all specific AD rights + standard rights)
	// This is what GENERIC_ALL maps to when stored in AD ACLs
	const adFullControl = 0x000f01ff

	var affected []types.ACLEntry

	for _, ace := range data.ACLEntries {
		// Check for raw GENERIC_ALL
		if (ace.AccessMask & genericAll) != 0 {
			affected = append(affected, ace)
			continue
		}
		// Check for Full Control (GENERIC_ALL mapped to AD rights)
		// The mask 0x000F01FF includes: DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | all DS rights
		if (ace.AccessMask & adFullControl) == adFullControl {
			affected = append(affected, ace)
		}
	}

	uniqueObjects := helpers.GetUniqueObjects(affected)
	totalInstances := len(affected)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "ACL GenericAll",
		Description: "GenericAll permission on sensitive AD objects. Full control over object (reset passwords, modify groups, etc.).",
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
	audit.MustRegister(NewGenericAllDetector())
}
