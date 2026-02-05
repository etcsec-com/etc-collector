package network

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DnsZoneTransferDetector checks for unrestricted DNS zone transfers
type DnsZoneTransferDetector struct {
	audit.BaseDetector
}

// NewDnsZoneTransferDetector creates a new detector
func NewDnsZoneTransferDetector() *DnsZoneTransferDetector {
	return &DnsZoneTransferDetector{
		BaseDetector: audit.NewBaseDetector("DNS_ZONE_TRANSFER_UNRESTRICTED", audit.CategoryNetwork),
	}
}

// Detect executes the detection
func (d *DnsZoneTransferDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// TODO: DNS zone data collection not yet implemented
	// Return an empty finding until DNS zone data is available

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "DNS Zone Transfer Unrestricted",
		Description: "DNS zones allowing zone transfers to any server. Attackers can enumerate DNS records to map internal network topology.",
		Count:       0,
		Details: map[string]interface{}{
			"status": "DNS zone data collection not yet implemented",
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDnsZoneTransferDetector())
}
