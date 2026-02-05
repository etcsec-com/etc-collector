package high

import (
	"context"
	"regexp"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ComputerTakeoverDetector detects RBCD attack paths
type ComputerTakeoverDetector struct {
	audit.BaseDetector
}

// NewComputerTakeoverDetector creates a new detector
func NewComputerTakeoverDetector() *ComputerTakeoverDetector {
	return &ComputerTakeoverDetector{
		BaseDetector: audit.NewBaseDetector("PATH_COMPUTER_TAKEOVER", audit.CategoryAttackPaths),
	}
}

var dcPattern = regexp.MustCompile(`(?i)^(dc|domain controller)`)

// Detect executes the detection
func (d *ComputerTakeoverDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var rbcdComputers []types.Computer
	var affected []types.Computer

	for _, c := range data.Computers {
		// Find computers with RBCD configured
		if len(c.AllowedToActOnBehalfOfOtherIdentity) == 0 {
			continue
		}
		rbcdComputers = append(rbcdComputers, c)

		// Check if privileged (DC or in Domain Controllers group)
		isDC := dcPattern.MatchString(c.SAMAccountName)
		for _, memberOf := range c.MemberOf {
			if strings.Contains(strings.ToLower(memberOf), "domain controllers") {
				isDC = true
				break
			}
		}

		if isDC || c.AdminCount {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "RBCD Computer Takeover Path",
		Description: "Privileged computers have Resource-Based Constrained Delegation configured. Attackers controlling the delegating principal can compromise these computers.",
		Count:       len(affected),
		Details: map[string]interface{}{
			"totalRbcdComputers":      len(rbcdComputers),
			"privilegedRbcdComputers": len(affected),
			"attackVector":            "Control delegating account → RBCD → Impersonate on target",
			"mitigation":              "Remove RBCD from privileged computers, monitor msDS-AllowedToActOnBehalfOfOtherIdentity",
		},
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewComputerTakeoverDetector())
}
