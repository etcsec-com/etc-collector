package password

import (
	"context"
	"reflect"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// UnixUserPasswordDetector detects accounts with Unix password attributes
type UnixUserPasswordDetector struct {
	audit.BaseDetector
}

// NewUnixUserPasswordDetector creates a new detector
func NewUnixUserPasswordDetector() *UnixUserPasswordDetector {
	return &UnixUserPasswordDetector{
		BaseDetector: audit.NewBaseDetector("UNIX_USER_PASSWORD", audit.CategoryPassword),
	}
}

// Detect executes the detection
func (d *UnixUserPasswordDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Unix password attributes to check
	unixAttributes := []string{
		"unixUserPassword",
		"userPassword",
	}

	var affected []types.User

	for _, u := range data.Users {
		// Use reflection to check for Unix password attributes
		val := reflect.ValueOf(u)
		for _, attr := range unixAttributes {
			field := val.FieldByName(attr)
			if field.IsValid() && !field.IsZero() {
				affected = append(affected, u)
				break
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Unix User Password",
		Description: "User accounts with Unix password attributes present. These may contain cleartext or weakly hashed passwords.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewUnixUserPasswordDetector())
}
