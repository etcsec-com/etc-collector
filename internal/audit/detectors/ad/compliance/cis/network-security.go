package cis

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NetworkSecurityDetector checks CIS network security compliance
type NetworkSecurityDetector struct {
	audit.BaseDetector
}

// NewNetworkSecurityDetector creates a new detector
func NewNetworkSecurityDetector() *NetworkSecurityDetector {
	return &NetworkSecurityDetector{
		BaseDetector: audit.NewBaseDetector("CIS_NETWORK_SECURITY", audit.CategoryCompliance),
	}
}

// Detect executes the detection
func (d *NetworkSecurityDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var issues []string

	// CIS 2.3.8.1: Microsoft network client: Digitally sign communications (always)
	// CIS 2.3.8.2: Microsoft network client: Digitally sign communications (if server agrees)
	// CIS 2.3.9.1: Microsoft network server: Digitally sign communications (always)
	// These settings would require GPO analysis - flag for manual review

	// Check LDAP signing via domain functional level hints
	if data.DomainInfo != nil {
		if data.DomainInfo.FunctionalLevelInt < 7 { // Windows Server 2016
			issues = append(issues, "CIS 2.3.11.8: Domain functional level may not enforce LDAP signing")
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "CIS Network Security Review Required",
		Description: "Network security settings require manual verification per CIS Benchmark. Check SMB signing, LDAP signing, and LDAP channel binding settings via GPO.",
		Count:       0,
		Details: map[string]interface{}{
			"framework": "CIS",
			"benchmark": "CIS Microsoft Windows Server Benchmark",
			"sections":  []string{"2.3.8 - Network client", "2.3.9 - Network server", "2.3.11 - Network security"},
			"note":      "GPO-based settings require manual verification",
		},
	}

	if len(issues) > 0 {
		finding.Count = 1
		finding.Details["violations"] = issues
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNetworkSecurityDetector())
}
