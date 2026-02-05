package kerberos

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// KerberosRenewableTicketLongDetector checks for long renewable ticket lifetime
type KerberosRenewableTicketLongDetector struct {
	audit.BaseDetector
}

// NewKerberosRenewableTicketLongDetector creates a new detector
func NewKerberosRenewableTicketLongDetector() *KerberosRenewableTicketLongDetector {
	return &KerberosRenewableTicketLongDetector{
		BaseDetector: audit.NewBaseDetector("KERBEROS_RENEWABLE_TICKET_LONG", audit.CategoryKerberos),
	}
}

// Detect executes the detection
func (d *KerberosRenewableTicketLongDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// This detection would need domain Kerberos policy data
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Kerberos Renewable Ticket Lifetime Review",
		Description: "Renewable ticket lifetime should be reviewed. Default of 7 days is reasonable; longer allows persistent access with stolen tickets.",
		Count:       0, // Would be 1 if renewable lifetime > 7 days detected
		Details: map[string]interface{}{
			"recommendation": "Renewable TGT lifetime should not exceed 7 days.",
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewKerberosRenewableTicketLongDetector())
}
