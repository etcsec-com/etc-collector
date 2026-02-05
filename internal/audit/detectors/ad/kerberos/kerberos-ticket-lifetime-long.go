package kerberos

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// KerberosTicketLifetimeLongDetector checks for long Kerberos ticket lifetime
type KerberosTicketLifetimeLongDetector struct {
	audit.BaseDetector
}

// NewKerberosTicketLifetimeLongDetector creates a new detector
func NewKerberosTicketLifetimeLongDetector() *KerberosTicketLifetimeLongDetector {
	return &KerberosTicketLifetimeLongDetector{
		BaseDetector: audit.NewBaseDetector("KERBEROS_TICKET_LIFETIME_LONG", audit.CategoryKerberos),
	}
}

// Detect executes the detection
func (d *KerberosTicketLifetimeLongDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// This detection would need domain Kerberos policy data
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Kerberos Ticket Lifetime Review",
		Description: "Kerberos ticket lifetime should be reviewed. Default of 10 hours is reasonable; longer lifetimes increase attack window.",
		Count:       0, // Would be 1 if ticket lifetime > 10 hours detected
		Details: map[string]interface{}{
			"recommendation": "TGT lifetime should not exceed 10 hours. Service tickets should not exceed 600 minutes.",
			"checkCommand":   "gpresult /r or check Default Domain Policy",
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewKerberosTicketLifetimeLongDetector())
}
