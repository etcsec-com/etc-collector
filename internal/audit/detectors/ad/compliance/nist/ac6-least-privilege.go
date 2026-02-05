package nist

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AC6LeastPrivilegeDetector checks NIST AC-6 least privilege compliance
type AC6LeastPrivilegeDetector struct {
	audit.BaseDetector
}

// NewAC6LeastPrivilegeDetector creates a new detector
func NewAC6LeastPrivilegeDetector() *AC6LeastPrivilegeDetector {
	return &AC6LeastPrivilegeDetector{
		BaseDetector: audit.NewBaseDetector("NIST_AC_6_LEAST_PRIVILEGE", audit.CategoryCompliance),
	}
}

// Detect executes the detection
func (d *AC6LeastPrivilegeDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var issues []string

	// AC-6(1): Authorize access to security functions
	// Check for users in multiple highly privileged groups
	usersInMultiplePrivGroups := 0
	for _, u := range data.Users {
		if !u.Enabled() {
			continue
		}
		privGroupCount := 0
		for _, memberOf := range u.MemberOf {
			memberOfLower := strings.ToLower(memberOf)
			if strings.Contains(memberOfLower, "domain admins") ||
				strings.Contains(memberOfLower, "enterprise admins") ||
				strings.Contains(memberOfLower, "schema admins") ||
				strings.Contains(memberOfLower, "account operators") ||
				strings.Contains(memberOfLower, "server operators") ||
				strings.Contains(memberOfLower, "backup operators") {
				privGroupCount++
			}
		}
		if privGroupCount > 1 {
			usersInMultiplePrivGroups++
		}
	}

	if usersInMultiplePrivGroups > 0 {
		issues = append(issues, "AC-6(1): Users in multiple privileged groups")
	}

	// AC-6(5): Privileged accounts - excessive domain admins
	daCount := 0
	for _, u := range data.Users {
		if !u.Enabled() {
			continue
		}
		for _, memberOf := range u.MemberOf {
			if strings.Contains(strings.ToLower(memberOf), "domain admins") {
				daCount++
				break
			}
		}
	}

	if daCount > 5 {
		issues = append(issues, "AC-6(5): Excessive Domain Admin accounts")
	}

	// AC-6(10): Prohibit non-privileged users from executing privileged functions
	// Check for regular users with adminCount set
	regularUsersWithAdmin := 0
	for _, u := range data.Users {
		if u.Enabled() && u.AdminCount && len(u.ServicePrincipalNames) == 0 {
			isInPrivGroup := false
			for _, memberOf := range u.MemberOf {
				if strings.Contains(strings.ToLower(memberOf), "domain admins") ||
					strings.Contains(strings.ToLower(memberOf), "enterprise admins") {
					isInPrivGroup = true
					break
				}
			}
			if !isInPrivGroup {
				regularUsersWithAdmin++
			}
		}
	}

	if regularUsersWithAdmin > 10 {
		issues = append(issues, "AC-6(10): Many accounts with adminCount outside standard admin groups")
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "NIST AC-6 Least Privilege Non-Compliant",
		Description: "Least privilege principles not fully implemented per NIST SP 800-53 AC-6 requirements.",
		Count:       0,
		Details: map[string]interface{}{
			"framework":                  "NIST",
			"control":                    "AC-6",
			"publication":                "SP 800-53",
			"domainAdmins":               daCount,
			"usersInMultiplePrivGroups":  usersInMultiplePrivGroups,
			"regularUsersWithAdminCount": regularUsersWithAdmin,
		},
	}

	if len(issues) > 0 {
		finding.Count = 1
		finding.Details["violations"] = issues
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAC6LeastPrivilegeDetector())
}
