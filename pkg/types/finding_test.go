package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSeverityWeight(t *testing.T) {
	tests := []struct {
		severity Severity
		expected int
	}{
		{SeverityCritical, 100},
		{SeverityHigh, 50},
		{SeverityMedium, 20},
		{SeverityLow, 5},
		{SeverityInfo, 1},
		{Severity("unknown"), 0},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.severity.Weight())
		})
	}
}

func TestCalculateScore(t *testing.T) {
	tests := []struct {
		name     string
		findings []Finding
		expected int
	}{
		{
			name:     "no findings - perfect score",
			findings: []Finding{},
			expected: 100,
		},
		{
			name: "single critical finding",
			findings: []Finding{
				{Type: "TEST", Severity: SeverityCritical, Count: 1},
			},
			expected: 90, // 100 - (100/1000)*100
		},
		{
			name: "multiple findings",
			findings: []Finding{
				{Type: "TEST1", Severity: SeverityCritical, Count: 1},
				{Type: "TEST2", Severity: SeverityHigh, Count: 1},
				{Type: "TEST3", Severity: SeverityMedium, Count: 1},
			},
			expected: 83, // 100 - ((100+50+20)/1000)*100 = 83
		},
		{
			name: "many findings - capped penalty",
			findings: []Finding{
				{Type: "TEST1", Severity: SeverityCritical, Count: 1},
				{Type: "TEST2", Severity: SeverityCritical, Count: 1},
				{Type: "TEST3", Severity: SeverityCritical, Count: 1},
				{Type: "TEST4", Severity: SeverityCritical, Count: 1},
				{Type: "TEST5", Severity: SeverityCritical, Count: 1},
				{Type: "TEST6", Severity: SeverityCritical, Count: 1},
				{Type: "TEST7", Severity: SeverityCritical, Count: 1},
				{Type: "TEST8", Severity: SeverityCritical, Count: 1},
				{Type: "TEST9", Severity: SeverityCritical, Count: 1},
				{Type: "TEST10", Severity: SeverityCritical, Count: 1},
				{Type: "TEST11", Severity: SeverityCritical, Count: 1},
			},
			expected: 0, // 11 * 100 = 1100, capped at 1000 -> score 0
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := CalculateScore(tt.findings)
			assert.Equal(t, tt.expected, score)
		})
	}
}

func TestCalculateGrade(t *testing.T) {
	tests := []struct {
		score    int
		expected string
	}{
		{100, "A"},
		{95, "A"},
		{90, "A"},
		{89, "B"},
		{80, "B"},
		{79, "C"},
		{70, "C"},
		{69, "D"},
		{60, "D"},
		{59, "F"},
		{0, "F"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			grade := CalculateGrade(tt.score)
			assert.Equal(t, tt.expected, grade)
		})
	}
}

func TestAuditStatistics(t *testing.T) {
	stats := NewAuditStatistics()

	assert.NotNil(t, stats)
	assert.NotNil(t, stats.BySeverity)
	assert.NotNil(t, stats.ByCategory)
	assert.Equal(t, 0, stats.TotalFindings)
}

func TestFindingJSON(t *testing.T) {
	finding := Finding{
		Type:        "TEST_FINDING",
		Severity:    SeverityHigh,
		Category:    "accounts",
		Title:       "Test Finding",
		Description: "This is a test finding",
		Count:       5,
	}

	data, err := finding.JSON()
	assert.NoError(t, err)
	assert.Contains(t, string(data), "TEST_FINDING")
	assert.Contains(t, string(data), "high")
}

func TestAuditResultJSON(t *testing.T) {
	result := AuditResult{
		Score: 85,
		Grade: "B",
		Findings: []Finding{
			{Type: "TEST", Severity: SeverityMedium, Count: 1},
		},
		Statistics: NewAuditStatistics(),
	}

	data, err := result.JSON()
	assert.NoError(t, err)
	assert.Contains(t, string(data), "85")
	assert.Contains(t, string(data), "B")

	prettyData, err := result.PrettyJSON()
	assert.NoError(t, err)
	assert.Contains(t, string(prettyData), "\n") // Pretty printed has newlines
}
