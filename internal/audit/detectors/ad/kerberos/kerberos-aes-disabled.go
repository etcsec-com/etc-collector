package kerberos

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// KerberosAesDisabledDetector checks for accounts with AES encryption disabled
type KerberosAesDisabledDetector struct {
	audit.BaseDetector
}

// NewKerberosAesDisabledDetector creates a new detector
func NewKerberosAesDisabledDetector() *KerberosAesDisabledDetector {
	return &KerberosAesDisabledDetector{
		BaseDetector: audit.NewBaseDetector("KERBEROS_AES_DISABLED", audit.CategoryKerberos),
	}
}

const (
	aesSupport       = 0x18 // AES128=0x8, AES256=0x10
	uacUseDESKeyOnly = 0x200000
)

// Detect executes the detection
func (d *KerberosAesDisabledDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []string

	for _, user := range data.Users {
		if user.Disabled {
			continue
		}

		// If msDS-SupportedEncryptionTypes is set and doesn't include AES
		if user.SupportedEncryptionTypes > 0 && (user.SupportedEncryptionTypes&aesSupport) == 0 {
			affected = append(affected, user.SAMAccountName)
			continue
		}

		// If UAC indicates DES-only
		if (user.UserAccountControl & uacUseDESKeyOnly) != 0 {
			affected = append(affected, user.SAMAccountName)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "AES Encryption Disabled",
		Description: "User accounts with AES Kerberos encryption disabled. Forces use of weaker DES/RC4 encryption vulnerable to offline attacks.",
		Count:       len(affected),
	}

	if len(affected) > 0 {
		finding.AffectedEntities = toAffectedUserNameEntitiesAes(affected)
	}

	return []types.Finding{finding}
}

// toAffectedUserNameEntitiesAes converts a list of usernames to affected entities
func toAffectedUserNameEntitiesAes(names []string) []types.AffectedEntity {
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
	audit.MustRegister(NewKerberosAesDisabledDetector())
}
