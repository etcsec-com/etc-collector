package gpo

import (
	"context"
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// WeakPasswordPolicyDetector checks for weak password policy in GPO
type WeakPasswordPolicyDetector struct {
	audit.BaseDetector
}

// NewWeakPasswordPolicyDetector creates a new detector
func NewWeakPasswordPolicyDetector() *WeakPasswordPolicyDetector {
	return &WeakPasswordPolicyDetector{
		BaseDetector: audit.NewBaseDetector("GPO_WEAK_PASSWORD_POLICY", audit.CategoryGPO),
	}
}

// Detect executes the detection
func (d *WeakPasswordPolicyDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	minLength := 0
	if data.DomainInfo != nil {
		minLength = data.DomainInfo.MinPwdLength
	}

	isWeak := minLength < 12

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Weak Password Policy",
		Description: fmt.Sprintf("Domain password policy requires only %d characters minimum. Microsoft recommends at least 12 characters for standard accounts, 14+ for privileged accounts.", minLength),
		Count:       0,
	}

	if isWeak {
		finding.Count = 1
		finding.AffectedEntities = []types.AffectedEntity{
			{Type: "gpo", Name: "Default Domain Policy"},
		}
		finding.Details = map[string]interface{}{
			"currentMinLength":     minLength,
			"recommendedMinLength": 12,
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewWeakPasswordPolicyDetector())
}
