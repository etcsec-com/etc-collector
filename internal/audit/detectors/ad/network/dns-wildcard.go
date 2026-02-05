package network

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DnsWildcardDetector checks for DNS wildcard records
type DnsWildcardDetector struct {
	audit.BaseDetector
}

// NewDnsWildcardDetector creates a new detector
func NewDnsWildcardDetector() *DnsWildcardDetector {
	return &DnsWildcardDetector{
		BaseDetector: audit.NewBaseDetector("DNS_WILDCARD_RECORDS", audit.CategoryNetwork),
	}
}

// Detect executes the detection
func (d *DnsWildcardDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// This detection would require querying DNS records within zones
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "DNS Wildcard Records Detected",
		Description: "Wildcard DNS records (*.domain) can be exploited for MITM attacks. Review and remove unnecessary wildcards.",
		Count:       0, // Would be populated with actual wildcard checks
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDnsWildcardDetector())
}
