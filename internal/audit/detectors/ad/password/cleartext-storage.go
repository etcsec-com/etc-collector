package password

import (
	"context"
	"reflect"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// CleartextStorageDetector detects accounts with cleartext password storage attributes
type CleartextStorageDetector struct {
	audit.BaseDetector
}

// NewCleartextStorageDetector creates a new detector
func NewCleartextStorageDetector() *CleartextStorageDetector {
	return &CleartextStorageDetector{
		BaseDetector: audit.NewBaseDetector("PASSWORD_CLEARTEXT_STORAGE", audit.CategoryPassword),
	}
}

// Detect executes the detection
func (d *CleartextStorageDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Cleartext password attributes to check
	cleartextAttributes := []string{
		"unixUserPassword",
		"userPassword",
		"unicodePwd",         // Should never be readable
		"msDS-ManagedPassword", // gMSA - should be protected
		"ms-Mcs-AdmPwd",       // LAPS - cleartext by design, but should be protected
	}

	var affected []types.User

	for _, u := range data.Users {
		// Use reflection to check for cleartext password attributes
		val := reflect.ValueOf(u)
		for _, attr := range cleartextAttributes {
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
		Title:       "Cleartext Password Storage",
		Description: "User accounts with attributes that may store passwords in cleartext or reversible format. These attributes (userPassword, unixUserPassword) can be read by attackers with LDAP access.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewCleartextStorageDetector())
}
