package replication

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DuplicateSpnDetector detects duplicate SPNs
type DuplicateSpnDetector struct {
	audit.BaseDetector
}

// NewDuplicateSpnDetector creates a new detector
func NewDuplicateSpnDetector() *DuplicateSpnDetector {
	return &DuplicateSpnDetector{
		BaseDetector: audit.NewBaseDetector("DUPLICATE_SPN", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *DuplicateSpnDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Build SPN to DN mapping
	spnMap := make(map[string][]string)

	for _, u := range data.Users {
		for _, spn := range u.ServicePrincipalNames {
			spnMap[spn] = append(spnMap[spn], u.DN)
		}
	}

	for _, c := range data.Computers {
		for _, spn := range c.ServicePrincipalNames {
			spnMap[spn] = append(spnMap[spn], c.DN)
		}
	}

	// Find duplicate SPNs
	var affectedDNs []string
	for _, dns := range spnMap {
		if len(dns) > 1 {
			affectedDNs = append(affectedDNs, dns...)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Duplicate SPN",
		Description: "Service Principal Name registered multiple times. Can cause Kerberos authentication failures.",
		Count:       len(affectedDNs),
	}

	if data.IncludeDetails && len(affectedDNs) > 0 {
		entities := make([]types.AffectedEntity, len(affectedDNs))
		for i, dn := range affectedDNs {
			entities[i] = types.AffectedEntity{
				Type:           "object",
				SAMAccountName: dn,
			}
		}
		finding.AffectedEntities = entities
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDuplicateSpnDetector())
}
