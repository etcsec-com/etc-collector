package password

import (
	"context"
	"regexp"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// InDescriptionDetector detects accounts with passwords in the description field
type InDescriptionDetector struct {
	audit.BaseDetector
}

// NewInDescriptionDetector creates a new detector
func NewInDescriptionDetector() *InDescriptionDetector {
	return &InDescriptionDetector{
		BaseDetector: audit.NewBaseDetector("PASSWORD_IN_DESCRIPTION", audit.CategoryPassword),
	}
}

// Detect executes the detection
func (d *InDescriptionDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Password patterns in description
	passwordPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)password\s*[:=]\s*\S+`),
		regexp.MustCompile(`(?i)pwd\s*[:=]\s*\S+`),
		regexp.MustCompile(`(?i)pass\s*[:=]\s*\S+`),
		regexp.MustCompile(`(?i)motdepasse\s*[:=]\s*\S+`),
		regexp.MustCompile(`(?i)\bP@ssw0rd\b`),
		regexp.MustCompile(`(?i)\bPassword123\b`),
	}

	var affected []types.User

	for _, u := range data.Users {
		description := u.Description
		if description == "" {
			continue
		}

		for _, pattern := range passwordPatterns {
			if pattern.MatchString(description) {
				affected = append(affected, u)
				break
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Password in Description",
		Description: "User accounts with passwords or password-like strings in the description field. Cleartext credential exposure.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewInDescriptionDetector())
}
