package moderate

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ForceChangePasswordDetector detects ForceChangePassword extended right
type ForceChangePasswordDetector struct {
	audit.BaseDetector
}

// NewForceChangePasswordDetector creates a new detector
func NewForceChangePasswordDetector() *ForceChangePasswordDetector {
	return &ForceChangePasswordDetector{
		BaseDetector: audit.NewBaseDetector("ACL_FORCECHANGEPASSWORD", audit.CategoryPermissions),
	}
}

// Detect executes the detection
func (d *ForceChangePasswordDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	const forceChangePasswordGUID = "00299570-246d-11d0-a768-00aa006e0529"

	var affected []types.ACLEntry

	for _, ace := range data.ACLEntries {
		if strings.ToLower(ace.ObjectType) == forceChangePasswordGUID {
			affected = append(affected, ace)
		}
	}

	uniqueObjects := helpers.GetUniqueObjects(affected)
	totalInstances := len(affected)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "ACL Force Change Password",
		Description: "ExtendedRight to force password change on user accounts. Can reset passwords without knowing current password.",
		Count:       len(uniqueObjects),
	}

	if totalInstances != len(uniqueObjects) {
		finding.TotalInstances = totalInstances
	}

	if data.IncludeDetails && len(uniqueObjects) > 0 {
		entities := make([]types.AffectedEntity, len(uniqueObjects))
		for i, dn := range uniqueObjects {
			entities[i] = types.AffectedEntity{
				Type: "user",
				DN:   dn,
			}
		}
		finding.AffectedEntities = entities
	}

	return []types.Finding{finding}
}

// UserForceChangePasswordDetector detects User-Force-Change-Password rights
type UserForceChangePasswordDetector struct {
	audit.BaseDetector
}

// NewUserForceChangePasswordDetector creates a new detector
func NewUserForceChangePasswordDetector() *UserForceChangePasswordDetector {
	return &UserForceChangePasswordDetector{
		BaseDetector: audit.NewBaseDetector("ACL_USER_FORCE_CHANGE_PASSWORD", audit.CategoryPermissions),
	}
}

// Detect executes the detection
func (d *UserForceChangePasswordDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// User-Force-Change-Password: 00299570-246d-11d0-a768-00aa006e0529
	const forceChangePasswordGUID = "00299570-246d-11d0-a768-00aa006e0529"

	var affected []types.ACLEntry

	for _, ace := range data.ACLEntries {
		if strings.ToLower(ace.ObjectType) == forceChangePasswordGUID {
			affected = append(affected, ace)
		}
	}

	uniqueObjects := helpers.GetUniqueObjects(affected)
	totalInstances := len(affected)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "User-Force-Change-Password Rights",
		Description: "Principals with rights to force password change on user accounts. Can reset passwords to take over accounts.",
		Count:       len(uniqueObjects),
	}

	if totalInstances != len(uniqueObjects) {
		finding.TotalInstances = totalInstances
	}

	if data.IncludeDetails && len(uniqueObjects) > 0 {
		entities := make([]types.AffectedEntity, len(uniqueObjects))
		for i, dn := range uniqueObjects {
			entities[i] = types.AffectedEntity{
				Type: "user",
				DN:   dn,
			}
		}
		finding.AffectedEntities = entities
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewForceChangePasswordDetector())
	audit.MustRegister(NewUserForceChangePasswordDetector())
}
