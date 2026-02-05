package other

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NtlmRelayOpportunityDetector detects NTLM relay opportunities
type NtlmRelayOpportunityDetector struct {
	audit.BaseDetector
}

// NewNtlmRelayOpportunityDetector creates a new detector
func NewNtlmRelayOpportunityDetector() *NtlmRelayOpportunityDetector {
	return &NtlmRelayOpportunityDetector{
		BaseDetector: audit.NewBaseDetector("NTLM_RELAY_OPPORTUNITY", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *NtlmRelayOpportunityDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	if data.DomainInfo == nil {
		return []types.Finding{{
			Type:        d.ID(),
			Severity:    types.SeverityMedium,
			Category:    string(d.Category()),
			Title:       "NTLM Relay Opportunity",
			Description: "Unable to check LDAP signing configuration.",
			Count:       0,
		}}
	}

	ldapSigningRequired := data.DomainInfo.LDAPSigningRequired
	channelBindingRequired := data.DomainInfo.ChannelBindingRequired

	isVulnerable := !ldapSigningRequired || !channelBindingRequired

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "NTLM Relay Opportunity",
		Description: "LDAP signing or channel binding not enforced. Enables NTLM relay attacks.",
		Count:       0,
	}

	if isVulnerable {
		finding.Count = 1
		if data.IncludeDetails {
			finding.AffectedEntities = []types.AffectedEntity{{
				Type:           "domain",
				SAMAccountName: data.DomainInfo.DN,
			}}
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNtlmRelayOpportunityDetector())
}
