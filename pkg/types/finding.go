// Package types defines common types used across the application
package types

import (
	"encoding/json"
	"time"
)

// Severity represents the severity level of a finding
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Weight returns the scoring weight for this severity
func (s Severity) Weight() int {
	switch s {
	case SeverityCritical:
		return 100
	case SeverityHigh:
		return 50
	case SeverityMedium:
		return 20
	case SeverityLow:
		return 5
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// Finding represents a security finding
type Finding struct {
	Type             string                 `json:"type"`
	Severity         Severity               `json:"severity"`
	Category         string                 `json:"category"`
	Title            string                 `json:"title"`
	Description      string                 `json:"description"`
	Count            int                    `json:"count"`
	TotalInstances   int                    `json:"totalInstances,omitempty"`
	AffectedEntities []AffectedEntity       `json:"affectedEntities,omitempty"`
	Details          map[string]interface{} `json:"details,omitempty"`
}

// AffectedEntity represents an affected AD object
type AffectedEntity struct {
	Type           string `json:"type"` // "user", "group", "computer", "gpo", "site", "trust"
	Name           string `json:"name,omitempty"` // Generic name field for entities without SAMAccountName
	DN             string `json:"dn"`
	SAMAccountName string `json:"sAMAccountName"`
	DisplayName    string `json:"displayName,omitempty"`
	Description    string `json:"description,omitempty"`

	// For users
	UserPrincipalName string `json:"userPrincipalName,omitempty"`
	Mail              string `json:"mail,omitempty"`
	LastLogon         string `json:"lastLogon,omitempty"`
	PasswordLastSet   string `json:"pwdLastSet,omitempty"`
	Enabled           *bool  `json:"enabled,omitempty"`
	AdminCount        *int   `json:"adminCount,omitempty"`
	MemberOf          []string `json:"memberOf,omitempty"`

	// For computers
	OperatingSystem        string `json:"operatingSystem,omitempty"`
	OperatingSystemVersion string `json:"operatingSystemVersion,omitempty"`
	DNSHostName            string `json:"dnsHostName,omitempty"`

	// For groups
	MemberCount int `json:"memberCount,omitempty"`
}

// FindingSummary is a compact representation of a finding
type FindingSummary struct {
	Type     string   `json:"type"`
	Severity Severity `json:"severity"`
	Count    int      `json:"count"`
}

// AuditResult represents the result of an audit
type AuditResult struct {
	Timestamp  time.Time           `json:"timestamp"`
	Duration   time.Duration       `json:"duration"`
	Score      int                 `json:"score"`
	Grade      string              `json:"grade"`
	Provider   string              `json:"provider"`
	Domain     string              `json:"domain,omitempty"`
	Findings   []Finding           `json:"findings"`
	Statistics *AuditStatistics    `json:"statistics"`
	Summary    []FindingSummary    `json:"summary,omitempty"`
}

// AuditStatistics contains statistical information about an audit
type AuditStatistics struct {
	TotalFindings    int                     `json:"totalFindings"`
	BySeverity       map[Severity]int        `json:"bySeverity"`
	ByCategory       map[string]int          `json:"byCategory"`
	UsersScanned     int                     `json:"usersScanned"`
	GroupsScanned    int                     `json:"groupsScanned"`
	ComputersScanned int                     `json:"computersScanned"`
}

// NewAuditStatistics creates a new AuditStatistics with initialized maps
func NewAuditStatistics() *AuditStatistics {
	return &AuditStatistics{
		BySeverity: make(map[Severity]int),
		ByCategory: make(map[string]int),
	}
}

// CalculateScore calculates the security score from findings (0-100, 100 = perfect)
func CalculateScore(findings []Finding) int {
	if len(findings) == 0 {
		return 100
	}

	totalPenalty := 0
	for _, f := range findings {
		totalPenalty += f.Severity.Weight()
	}

	// Cap penalty
	maxPenalty := 1000
	if totalPenalty > maxPenalty {
		totalPenalty = maxPenalty
	}

	score := 100 - (totalPenalty * 100 / maxPenalty)
	if score < 0 {
		score = 0
	}

	return score
}

// CalculateGrade returns a letter grade based on score
func CalculateGrade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

// JSON returns the JSON representation of the finding
func (f Finding) JSON() ([]byte, error) {
	return json.Marshal(f)
}

// JSON returns the JSON representation of the audit result
func (r AuditResult) JSON() ([]byte, error) {
	return json.Marshal(r)
}

// PrettyJSON returns pretty-printed JSON
func (r AuditResult) PrettyJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
