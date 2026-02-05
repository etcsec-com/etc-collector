package anssi

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// R5SegregationDetector checks ANSSI R5 segregation compliance
type R5SegregationDetector struct {
	audit.BaseDetector
}

// NewR5SegregationDetector creates a new detector
func NewR5SegregationDetector() *R5SegregationDetector {
	return &R5SegregationDetector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R5_SEGREGATION", audit.CategoryCompliance),
	}
}

// Detect executes the detection
func (d *R5SegregationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var issues []string

	// Check for users in multiple privileged groups (no segregation)
	for _, u := range data.Users {
		if !u.Enabled() {
			continue
		}

		privilegedGroupCount := 0
		for _, memberOf := range u.MemberOf {
			memberOfLower := strings.ToLower(memberOf)
			if strings.Contains(memberOfLower, "domain admins") ||
				strings.Contains(memberOfLower, "enterprise admins") ||
				strings.Contains(memberOfLower, "schema admins") ||
				strings.Contains(memberOfLower, "account operators") ||
				strings.Contains(memberOfLower, "backup operators") {
				privilegedGroupCount++
			}
		}

		if privilegedGroupCount > 1 {
			issues = append(issues, "Users in multiple privileged groups (no segregation)")
			break
		}
	}

	// Check if standard users have admin access
	standardUsersWithAdmin := 0
	for _, u := range data.Users {
		if !u.Enabled() {
			continue
		}
		hasServiceSPN := len(u.ServicePrincipalNames) > 0
		isAdmin := u.AdminCount

		if !hasServiceSPN && isAdmin {
			standardUsersWithAdmin++
		}
	}

	if standardUsersWithAdmin > 20 {
		issues = append(issues, "Many standard users with admin privileges")
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "ANSSI R5 - Segregation Non-Compliant",
		Description: "Privilege segregation does not meet ANSSI R5 recommendations. Separate admin roles and minimize privilege overlap.",
		Count:       0,
	}

	if len(issues) > 0 {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"violations":             issues,
			"framework":              "ANSSI",
			"control":                "R5",
			"standardUsersWithAdmin": standardUsersWithAdmin,
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewR5SegregationDetector())
}
