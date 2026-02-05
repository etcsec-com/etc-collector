package gpo

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PasswordInSysvolDetector checks for potential passwords in GPO SYSVOL
type PasswordInSysvolDetector struct {
	audit.BaseDetector
}

// NewPasswordInSysvolDetector creates a new detector
func NewPasswordInSysvolDetector() *PasswordInSysvolDetector {
	return &PasswordInSysvolDetector{
		BaseDetector: audit.NewBaseDetector("GPO_PASSWORD_IN_SYSVOL", audit.CategoryGPO),
	}
}

var riskyPatterns = []string{
	"password",
	"credential",
	"local admin",
	"service account",
	"scheduled task",
	"drive map",
}

// Detect executes the detection
func (d *PasswordInSysvolDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []string

	for _, gpo := range data.GPOs {
		gpoName := strings.ToLower(gpo.DisplayName)
		if gpoName == "" {
			gpoName = strings.ToLower(gpo.CN)
		}
		gpoPath := strings.ToLower(gpo.FilePath)

		for _, pattern := range riskyPatterns {
			if strings.Contains(gpoName, pattern) || strings.Contains(gpoPath, pattern) {
				name := gpo.DisplayName
				if name == "" {
					name = gpo.CN
				}
				affected = append(affected, name)
				break
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Potential Passwords in GPO SYSVOL",
		Description: "GPOs that may contain cleartext passwords in SYSVOL (cPassword vulnerability MS14-025). Group Policy Preferences stored passwords that can be easily decrypted.",
		Count:       len(affected),
		Details: map[string]interface{}{
			"recommendation": "Scan SYSVOL for Groups.xml, Services.xml, ScheduledTasks.xml, DataSources.xml containing cpassword. Use tools like Get-GPPPassword or gpp-decrypt.",
			"reference":      "MS14-025",
			"gposScanned":    len(data.GPOs),
		},
	}

	if len(affected) > 0 {
		finding.AffectedEntities = toAffectedGPOEntities(affected)
		finding.Details["note"] = "Found GPO(s) with names suggesting password storage. Manual SYSVOL scan required."
	} else {
		finding.Details["note"] = "No GPOs with suspicious names found. Manual SYSVOL scan still recommended."
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPasswordInSysvolDetector())
}
