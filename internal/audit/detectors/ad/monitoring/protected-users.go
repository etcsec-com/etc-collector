package monitoring

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ProtectedUsersDetector checks if Protected Users group is being used
type ProtectedUsersDetector struct {
	audit.BaseDetector
}

// NewProtectedUsersDetector creates a new detector
func NewProtectedUsersDetector() *ProtectedUsersDetector {
	return &ProtectedUsersDetector{
		BaseDetector: audit.NewBaseDetector("NO_PROTECTED_USERS_MONITORING", audit.CategoryMonitoring),
	}
}

// Detect executes the detection
func (d *ProtectedUsersDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Find the Protected Users group
	var protectedUsersGroup *types.Group
	for i := range data.Groups {
		name := strings.ToLower(data.Groups[i].SAMAccountName)
		if name == "" {
			name = strings.ToLower(data.Groups[i].DisplayName)
		}
		if name == "protected users" || strings.Contains(strings.ToLower(data.Groups[i].DistinguishedName), "cn=protected users") {
			protectedUsersGroup = &data.Groups[i]
			break
		}
	}

	// Get privileged users who should be in Protected Users
	var privilegedUsers []types.User
	for _, user := range data.Users {
		if user.AdminCount && !user.Disabled {
			privilegedUsers = append(privilegedUsers, user)
		}
	}

	// Check which privileged users are NOT in Protected Users
	var notInProtectedUsers []string
	for _, user := range privilegedUsers {
		isInProtectedUsers := false
		for _, groupDN := range user.MemberOf {
			groupDNLower := strings.ToLower(groupDN)
			if strings.Contains(groupDNLower, "cn=protected users") {
				isInProtectedUsers = true
				break
			}
			if protectedUsersGroup != nil && groupDNLower == strings.ToLower(protectedUsersGroup.DistinguishedName) {
				isInProtectedUsers = true
				break
			}
		}
		if !isInProtectedUsers {
			notInProtectedUsers = append(notInProtectedUsers, user.SAMAccountName)
		}
	}

	groupExists := protectedUsersGroup != nil
	groupMemberCount := 0
	if protectedUsersGroup != nil {
		groupMemberCount = len(protectedUsersGroup.Member)
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Protected Users Group Not Utilized",
		Description: "Privileged accounts are not members of the Protected Users group. This group provides additional protections against credential theft.",
		Count:       len(notInProtectedUsers),
		Details: map[string]interface{}{
			"groupExists":             groupExists,
			"currentMembers":          groupMemberCount,
			"totalPrivilegedAccounts": len(privilegedUsers),
			"notInGroup":              len(notInProtectedUsers),
			"protections": []string{
				"NTLM authentication disabled",
				"Kerberos DES/RC4 encryption disabled",
				"Kerberos TGT lifetime reduced to 4 hours",
				"Credential delegation disabled",
				"Cached credentials not stored",
			},
			"recommendation": "Add all privileged/admin accounts to Protected Users group for enhanced credential protection.",
		},
	}

	if len(notInProtectedUsers) > 0 {
		finding.AffectedEntities = toAffectedUserNameEntitiesProtected(notInProtectedUsers)
	}

	return []types.Finding{finding}
}

// toAffectedUserNameEntitiesProtected converts a list of usernames to affected entities
func toAffectedUserNameEntitiesProtected(names []string) []types.AffectedEntity {
	entities := make([]types.AffectedEntity, len(names))
	for i, name := range names {
		entities[i] = types.AffectedEntity{
			Type:           "user",
			SAMAccountName: name,
		}
	}
	return entities
}

func init() {
	audit.MustRegister(NewProtectedUsersDetector())
}
