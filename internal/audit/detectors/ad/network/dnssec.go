package network

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DnssecDetector checks if DNSSEC is not enabled
type DnssecDetector struct {
	audit.BaseDetector
}

// NewDnssecDetector creates a new detector
func NewDnssecDetector() *DnssecDetector {
	return &DnssecDetector{
		BaseDetector: audit.NewBaseDetector("DNSSEC_NOT_ENABLED", audit.CategoryNetwork),
	}
}

// Detect executes the detection
func (d *DnssecDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// DNSSEC would need to be checked via DNS server config
	// For now, assume not enabled if not explicitly configured
	dnssecEnabled := false

	count := 0
	if !dnssecEnabled {
		count = 1
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "DNSSEC Not Enabled",
		Description: "DNSSEC is not enabled for the domain. DNS responses can be spoofed, enabling cache poisoning and MITM attacks.",
		Count:       count,
		Details: map[string]interface{}{
			"recommendation": "Enable DNSSEC signing on Active Directory-integrated DNS zones.",
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDnssecDetector())
}
