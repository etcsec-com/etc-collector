package network

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DnsDynamicUpdateDetector checks for insecure DNS dynamic updates
type DnsDynamicUpdateDetector struct {
	audit.BaseDetector
}

// NewDnsDynamicUpdateDetector creates a new detector
func NewDnsDynamicUpdateDetector() *DnsDynamicUpdateDetector {
	return &DnsDynamicUpdateDetector{
		BaseDetector: audit.NewBaseDetector("DNS_DYNAMIC_UPDATE_INSECURE", audit.CategoryNetwork),
	}
}

// Detect executes the detection
func (d *DnsDynamicUpdateDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// TODO: DNS zone data collection not yet implemented
	// Return an empty finding until DNS zone data is available

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "DNS Dynamic Update Insecure",
		Description: "DNS zones allowing non-secure dynamic updates. Attackers can inject malicious DNS records without authentication.",
		Count:       0,
		Details: map[string]interface{}{
			"status": "DNS zone data collection not yet implemented",
		},
	}

	return []types.Finding{finding}
}

func toAffectedZoneEntities(names []string) []types.AffectedEntity {
	entities := make([]types.AffectedEntity, len(names))
	for i, name := range names {
		entities[i] = types.AffectedEntity{
			Type: "dnszone",
			Name: name,
		}
	}
	return entities
}

func init() {
	audit.MustRegister(NewDnsDynamicUpdateDetector())
}
