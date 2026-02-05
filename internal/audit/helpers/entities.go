// Package helpers provides utility functions for audit detectors
package helpers

import (
	"strings"
	"time"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ToAffectedUserEntities converts users to affected entities
func ToAffectedUserEntities(users []types.User) []types.AffectedEntity {
	entities := make([]types.AffectedEntity, len(users))
	for i, u := range users {
		enabled := !u.Disabled
		adminCount := 0
		if u.AdminCount {
			adminCount = 1
		}
		entities[i] = types.AffectedEntity{
			Type:              "user",
			DN:                u.DN,
			SAMAccountName:    u.SAMAccountName,
			DisplayName:       u.DisplayName,
			Description:       u.Description,
			UserPrincipalName: u.UserPrincipalName,
			Mail:              u.Mail,
			LastLogon:         FormatTime(u.LastLogon),
			PasswordLastSet:   FormatTime(u.PasswordLastSet),
			Enabled:           &enabled,
			AdminCount:        &adminCount,
			MemberOf:          u.MemberOf,
		}
	}
	return entities
}

// ToAffectedComputerEntities converts computers to affected entities
func ToAffectedComputerEntities(computers []types.Computer) []types.AffectedEntity {
	entities := make([]types.AffectedEntity, len(computers))
	for i, c := range computers {
		enabled := !c.Disabled
		entities[i] = types.AffectedEntity{
			Type:                   "computer",
			DN:                     c.DN,
			SAMAccountName:         c.SAMAccountName,
			DNSHostName:            c.DNSHostName,
			Description:            c.Description,
			OperatingSystem:        c.OperatingSystem,
			OperatingSystemVersion: c.OperatingSystemVersion,
			LastLogon:              FormatTime(c.LastLogon),
			PasswordLastSet:        FormatTime(c.PasswordLastSet),
			Enabled:                &enabled,
		}
	}
	return entities
}

// ToAffectedGroupEntities converts groups to affected entities
func ToAffectedGroupEntities(groups []types.Group) []types.AffectedEntity {
	entities := make([]types.AffectedEntity, len(groups))
	for i, g := range groups {
		entities[i] = types.AffectedEntity{
			Type:           "group",
			DN:             g.DN,
			SAMAccountName: g.SAMAccountName,
			Description:    g.Description,
			MemberCount:    len(g.Members),
		}
	}
	return entities
}

// FormatTime formats time for display
func FormatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

// ContainsGroupCI checks if any memberOf DN contains the group name (case-insensitive)
func ContainsGroupCI(memberOf []string, groupName string) bool {
	lowerGroup := strings.ToLower(groupName)
	for _, dn := range memberOf {
		if strings.Contains(strings.ToLower(dn), "cn="+lowerGroup) {
			return true
		}
	}
	return false
}

// IsInAnyGroup checks if user is in any of the specified groups
func IsInAnyGroup(memberOf []string, groups []string) bool {
	for _, g := range groups {
		if ContainsGroupCI(memberOf, g) {
			return true
		}
	}
	return false
}

// AdminGroups is the list of standard admin groups
var AdminGroups = []string{
	"Domain Admins",
	"Enterprise Admins",
	"Schema Admins",
	"Administrators",
	"Account Operators",
	"Server Operators",
	"Backup Operators",
	"Print Operators",
}

// GetUniqueObjects returns unique object DNs from ACL entries
func GetUniqueObjects(entries []types.ACLEntry) []string {
	seen := make(map[string]bool)
	var result []string

	for _, ace := range entries {
		if !seen[ace.ObjectDN] {
			seen[ace.ObjectDN] = true
			result = append(result, ace.ObjectDN)
		}
	}

	return result
}
