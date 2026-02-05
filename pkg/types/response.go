// Package types defines common types used across the application
package types

import (
	"time"
)

// AuditResponse is the top-level response structure (matches TypeScript)
type AuditResponse struct {
	Success  bool         `json:"success"`
	Provider string       `json:"provider"`
	Audit    *AuditReport `json:"audit"`
}

// AuditReport is the main audit structure (matches TypeScript audit object)
type AuditReport struct {
	Accounts       *AccountsSection       `json:"accounts"`
	Computers      *FindingsSection       `json:"computers"`
	Groups         *FindingsSection       `json:"groups"`
	Security       *SecuritySection       `json:"security"`
	Permissions    *FindingsSection       `json:"permissions"`
	ADCS           *FindingsSection       `json:"adcs"`
	GPOSecurity    *FindingsSection       `json:"gpoSecurity"`
	TrustsAnalysis *FindingsSection       `json:"trustsAnalysis"`
	DomainConfig   *DomainConfigSection   `json:"domainConfig"`
	Temporal       *FindingsSection       `json:"temporal"`
	AttackGraph    *AttackGraphSection    `json:"attackGraph"`
	ExtendedConfig *FindingsSection       `json:"extendedConfig"`
	Summary        *SummarySection        `json:"summary"`
	Metadata       *MetadataSection       `json:"metadata"`
}

// AccountsSection groups account-related findings
type AccountsSection struct {
	Status     *FindingsSection `json:"status"`
	Privileged *FindingsSection `json:"privileged"`
	Dangerous  *FindingsSection `json:"dangerous"`
	Service    *FindingsSection `json:"service"`
}

// SecuritySection groups security-related findings
type SecuritySection struct {
	Passwords *FindingsSection `json:"passwords"`
	Kerberos  *FindingsSection `json:"kerberos"`
	Advanced  *FindingsSection `json:"advanced"`
}

// FindingsSection contains findings and total count
type FindingsSection struct {
	Findings []Finding `json:"findings"`
	Total    int       `json:"total"`
}

// DomainConfigSection contains domain configuration info
type DomainConfigSection struct {
	DomainInfo      *DomainInfo      `json:"domainInfo,omitempty"`
	PasswordPolicy  *PasswordPolicy  `json:"passwordPolicy,omitempty"`
	KerberosPolicy  *KerberosPolicy  `json:"kerberosPolicy,omitempty"`
	GPOSummary      *GPOSummary      `json:"gpoSummary,omitempty"`
	Trusts          []Trust          `json:"trusts,omitempty"`
}

// PasswordPolicy represents domain password policy
type PasswordPolicy struct {
	MinLength            int  `json:"minLength"`
	MaxAge               int  `json:"maxAge"`
	MinAge               int  `json:"minAge"`
	HistoryCount         int  `json:"historyCount"`
	ComplexityEnabled    bool `json:"complexityEnabled"`
	ReversibleEncryption bool `json:"reversibleEncryption"`
	LockoutThreshold     int  `json:"lockoutThreshold"`
	LockoutDuration      int  `json:"lockoutDuration"`
}

// KerberosPolicy represents domain Kerberos policy
type KerberosPolicy struct {
	MaxTicketAge    int `json:"maxTicketAge"`
	MaxRenewAge     int `json:"maxRenewAge"`
	MaxServiceAge   int `json:"maxServiceAge"`
	MaxClockSkew    int `json:"maxClockSkew"`
}

// GPOSummary contains GPO statistics
type GPOSummary struct {
	Total    int `json:"total"`
	Linked   int `json:"linked"`
	Unlinked int `json:"unlinked"`
	Disabled int `json:"disabled"`
}

// AttackGraphSection contains attack path analysis
type AttackGraphSection struct {
	Domain      string        `json:"domain"`
	Version     string        `json:"version"`
	GeneratedAt time.Time     `json:"generatedAt"`
	Stats       *AttackStats  `json:"stats"`
	Paths       []interface{} `json:"paths"`
	Targets     []interface{} `json:"targets"`
	UniqueNodes int           `json:"uniqueNodes"`
}

// AttackStats contains attack path statistics
type AttackStats struct {
	TotalPaths   int `json:"totalPaths"`
	CriticalPath int `json:"criticalPaths"`
	HighPaths    int `json:"highPaths"`
}

// SummarySection contains audit summary
type SummarySection struct {
	Objects *ObjectsSummary `json:"objects"`
	Risk    *RiskSummary    `json:"risk"`
}

// ObjectsSummary contains scanned object counts
type ObjectsSummary struct {
	Users         int `json:"users"`
	UsersEnabled  int `json:"users_enabled"`
	UsersDisabled int `json:"users_disabled"`
	Groups        int `json:"groups"`
	OUs           int `json:"ous"`
	Computers     int `json:"computers"`
}

// RiskSummary contains risk assessment
type RiskSummary struct {
	Score    float64          `json:"score"`
	Rating   string           `json:"rating"`
	Findings *FindingsSummary `json:"findings"`
}

// FindingsSummary contains finding counts by severity
type FindingsSummary struct {
	Critical       int `json:"critical"`
	High           int `json:"high"`
	Medium         int `json:"medium"`
	Low            int `json:"low"`
	Total          int `json:"total"`
	TotalInstances int `json:"totalInstances"`
}

// MetadataSection contains audit execution metadata
type MetadataSection struct {
	Provider  string            `json:"provider"`
	Domain    *DomainMetadata   `json:"domain"`
	Options   *OptionsMetadata  `json:"options"`
	Execution *ExecutionMetadata `json:"execution"`
}

// DomainMetadata contains domain connection info
type DomainMetadata struct {
	Name    string `json:"name"`
	BaseDN  string `json:"baseDN"`
	LDAPUrl string `json:"ldapUrl"`
}

// OptionsMetadata contains audit options
type OptionsMetadata struct {
	IncludeDetails   bool `json:"includeDetails"`
	IncludeComputers bool `json:"includeComputers"`
	IncludeConfig    bool `json:"includeConfig"`
}

// ExecutionMetadata contains execution timing
type ExecutionMetadata struct {
	Timestamp time.Time `json:"timestamp"`
	Duration  string    `json:"duration"`
}

// NewFindingsSection creates a new FindingsSection
func NewFindingsSection() *FindingsSection {
	return &FindingsSection{
		Findings: []Finding{},
		Total:    0,
	}
}

// AddFinding adds a finding to the section
func (fs *FindingsSection) AddFinding(f Finding) {
	fs.Findings = append(fs.Findings, f)
	fs.Total += f.Count
}

// categoryMapping maps Go categories to TS structure paths
var categoryMapping = map[string]string{
	"accounts":     "accounts.status",
	"privileged":   "accounts.privileged",
	"dangerous":    "accounts.dangerous",
	"service":      "accounts.service",
	"computers":    "computers",
	"groups":       "groups",
	"kerberos":     "security.kerberos",
	"password":     "security.passwords",
	"advanced":     "security.advanced",
	"permissions":  "permissions",
	"adcs":         "adcs",
	"gpo":          "gpoSecurity",
	"trusts":       "trustsAnalysis",
	"compliance":   "extendedConfig",
	"attack-paths": "attackGraph",
	"network":      "domainConfig",
	"monitoring":   "temporal",
}

// ConvertToTSFormat converts an AuditResult to TypeScript-compatible AuditResponse
func ConvertToTSFormat(result *AuditResult, ldapURL string, baseDN string, includeDetails bool) *AuditResponse {
	report := &AuditReport{
		Accounts: &AccountsSection{
			Status:     NewFindingsSection(),
			Privileged: NewFindingsSection(),
			Dangerous:  NewFindingsSection(),
			Service:    NewFindingsSection(),
		},
		Computers:      NewFindingsSection(),
		Groups:         NewFindingsSection(),
		Security: &SecuritySection{
			Passwords: NewFindingsSection(),
			Kerberos:  NewFindingsSection(),
			Advanced:  NewFindingsSection(),
		},
		Permissions:    NewFindingsSection(),
		ADCS:           NewFindingsSection(),
		GPOSecurity:    NewFindingsSection(),
		TrustsAnalysis: NewFindingsSection(),
		Temporal:       NewFindingsSection(),
		ExtendedConfig: NewFindingsSection(),
		DomainConfig:   &DomainConfigSection{},
		AttackGraph: &AttackGraphSection{
			Domain:      result.Domain,
			Version:     "1.0",
			GeneratedAt: result.Timestamp,
			Stats:       &AttackStats{},
			Paths:       []interface{}{},
			Targets:     []interface{}{},
		},
	}

	// Distribute findings to appropriate sections
	var totalInstances int
	severityCounts := make(map[Severity]int)

	for _, f := range result.Findings {
		severityCounts[f.Severity] += f.Count
		totalInstances += f.Count
		if f.TotalInstances > 0 {
			totalInstances += f.TotalInstances - f.Count
		}

		// Route finding to appropriate section based on category
		switch f.Category {
		case "accounts":
			// Sub-categorize accounts based on finding type
			if isPrivilegedFinding(f.Type) {
				report.Accounts.Privileged.AddFinding(f)
			} else if isDangerousFinding(f.Type) {
				report.Accounts.Dangerous.AddFinding(f)
			} else if isServiceFinding(f.Type) {
				report.Accounts.Service.AddFinding(f)
			} else {
				report.Accounts.Status.AddFinding(f)
			}
		case "computers":
			report.Computers.AddFinding(f)
		case "groups":
			report.Groups.AddFinding(f)
		case "kerberos":
			report.Security.Kerberos.AddFinding(f)
		case "password":
			report.Security.Passwords.AddFinding(f)
		case "advanced":
			report.Security.Advanced.AddFinding(f)
		case "permissions":
			report.Permissions.AddFinding(f)
		case "adcs":
			report.ADCS.AddFinding(f)
		case "gpo":
			report.GPOSecurity.AddFinding(f)
		case "trusts":
			report.TrustsAnalysis.AddFinding(f)
		case "compliance":
			report.ExtendedConfig.AddFinding(f)
		case "attack-paths":
			// Attack paths go to both attackGraph stats and security.advanced
			report.AttackGraph.Stats.TotalPaths += f.Count
			report.Security.Advanced.AddFinding(f)
		case "network":
			report.Security.Advanced.AddFinding(f)
		case "monitoring":
			report.Temporal.AddFinding(f)
		default:
			// Default to extendedConfig for unknown categories
			report.ExtendedConfig.AddFinding(f)
		}
	}

	// Build summary
	totalFindings := severityCounts[SeverityCritical] + severityCounts[SeverityHigh] +
		severityCounts[SeverityMedium] + severityCounts[SeverityLow]

	report.Summary = &SummarySection{
		Objects: &ObjectsSummary{
			Users:         result.Statistics.UsersScanned,
			UsersEnabled:  result.Statistics.UsersScanned, // TODO: track enabled/disabled separately
			UsersDisabled: 0,
			Groups:        result.Statistics.GroupsScanned,
			OUs:           0, // TODO: track OUs
			Computers:     result.Statistics.ComputersScanned,
		},
		Risk: &RiskSummary{
			Score:  float64(100 - result.Score), // Invert: Go score is 0-100 good, TS is 0-100 bad
			Rating: getRiskRating(result.Score),
			Findings: &FindingsSummary{
				Critical:       severityCounts[SeverityCritical],
				High:           severityCounts[SeverityHigh],
				Medium:         severityCounts[SeverityMedium],
				Low:            severityCounts[SeverityLow],
				Total:          totalFindings,
				TotalInstances: totalInstances,
			},
		},
	}

	// Build metadata
	report.Metadata = &MetadataSection{
		Provider: "active-directory",
		Domain: &DomainMetadata{
			Name:    result.Domain,
			BaseDN:  baseDN,
			LDAPUrl: ldapURL,
		},
		Options: &OptionsMetadata{
			IncludeDetails:   includeDetails,
			IncludeComputers: true,
			IncludeConfig:    true,
		},
		Execution: &ExecutionMetadata{
			Timestamp: result.Timestamp,
			Duration:  result.Duration.String(),
		},
	}

	return &AuditResponse{
		Success:  true,
		Provider: "ldap",
		Audit:    report,
	}
}

// getRiskRating returns the risk rating string based on score
func getRiskRating(score int) string {
	switch {
	case score >= 90:
		return "low"
	case score >= 70:
		return "medium"
	case score >= 50:
		return "high"
	default:
		return "critical"
	}
}

// isPrivilegedFinding checks if a finding type relates to privileged accounts
func isPrivilegedFinding(findingType string) bool {
	privilegedTypes := map[string]bool{
		"SENSITIVE_DELEGATION":         true,
		"DOMAIN_ADMIN_IN_DESCRIPTION":  true,
		"NOT_IN_PROTECTED_USERS":       true,
		"ADMIN_NO_SMARTCARD":           true,
		"ADMIN_ASREP_ROASTABLE":        true,
		"ADMIN_LOGON_COUNT_LOW":        true,
		"ADMIN_COUNT_ORPHANED":         true,
		"PRIVILEGED_ACCOUNT_SPN":       true,
		"EXCESSIVE_PRIVILEGED_ACCOUNTS": true,
	}
	return privilegedTypes[findingType]
}

// isDangerousFinding checks if a finding type relates to dangerous accounts
func isDangerousFinding(findingType string) bool {
	dangerousTypes := map[string]bool{
		"ACCOUNT_OPERATORS_MEMBER":    true,
		"BACKUP_OPERATORS_MEMBER":     true,
		"SERVER_OPERATORS_MEMBER":     true,
		"PRINT_OPERATORS_MEMBER":      true,
		"DNS_ADMINS_MEMBER":           true,
		"DANGEROUS_BUILTIN_MEMBERSHIP": true,
		"BUILTIN_MODIFIED":            true,
	}
	return dangerousTypes[findingType]
}

// isServiceFinding checks if a finding type relates to service accounts
func isServiceFinding(findingType string) bool {
	serviceTypes := map[string]bool{
		"SERVICE_ACCOUNT_INTERACTIVE":   true,
		"SERVICE_ACCOUNT_NAMING":        true,
		"SERVICE_ACCOUNT_NO_PREAUTH":    true,
		"SERVICE_ACCOUNT_OLD_PASSWORD":  true,
		"SERVICE_ACCOUNT_PRIVILEGED":    true,
		"SERVICE_ACCOUNT_WITH_SPN":      true,
		"KERBEROASTING_RISK":            true,
	}
	return serviceTypes[findingType]
}
