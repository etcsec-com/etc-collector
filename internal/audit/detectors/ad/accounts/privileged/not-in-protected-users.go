package privileged

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NotInProtectedUsersDetector detects privileged accounts not in Protected Users group
type NotInProtectedUsersDetector struct {
	audit.BaseDetector
}

// NewNotInProtectedUsersDetector creates a new detector
func NewNotInProtectedUsersDetector() *NotInProtectedUsersDetector {
	return &NotInProtectedUsersDetector{
		BaseDetector: audit.NewBaseDetector("NOT_IN_PROTECTED_USERS", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *NotInProtectedUsersDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	privilegedGroups := []string{"Domain Admins", "Enterprise Admins", "Schema Admins"}

	for _, u := range data.Users {
		if len(u.MemberOf) == 0 {
			continue
		}

		// Check if privileged
		isPrivileged := false
		for _, dn := range u.MemberOf {
			for _, group := range privilegedGroups {
				if strings.Contains(dn, "CN="+group) {
					isPrivileged = true
					break
				}
			}
			if isPrivileged {
				break
			}
		}

		if !isPrivileged {
			continue
		}

		// Check if in Protected Users
		isInProtectedUsers := false
		for _, dn := range u.MemberOf {
			if strings.Contains(dn, "CN=Protected Users") {
				isInProtectedUsers = true
				break
			}
		}

		if !isInProtectedUsers {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Not in Protected Users Group",
		Description: "Privileged accounts not in Protected Users group. Missing additional security protections.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNotInProtectedUsersDetector())
}
