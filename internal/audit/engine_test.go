package audit

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/etcsec-com/etc-collector/internal/providers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// testProvider implements providers.Provider for testing
type testProvider struct {
	users     []types.User
	groups    []types.Group
	computers []types.Computer
	domain    *types.DomainInfo
}

func (p *testProvider) Type() providers.ProviderType { return providers.ProviderTypeLDAP }
func (p *testProvider) Connect(ctx context.Context) error { return nil }
func (p *testProvider) Close() error { return nil }
func (p *testProvider) IsConnected() bool { return true }

func (p *testProvider) GetUsers(ctx context.Context, opts providers.QueryOptions) ([]types.User, error) {
	return p.users, nil
}

func (p *testProvider) GetGroups(ctx context.Context, opts providers.QueryOptions) ([]types.Group, error) {
	return p.groups, nil
}

func (p *testProvider) GetComputers(ctx context.Context, opts providers.QueryOptions) ([]types.Computer, error) {
	return p.computers, nil
}

func (p *testProvider) GetDomainInfo(ctx context.Context) (*types.DomainInfo, error) {
	return p.domain, nil
}

// testDetector is a simple detector for testing
type testDetector struct {
	BaseDetector
	findings []types.Finding
}

func (d *testDetector) Detect(ctx context.Context, data *DetectorData) []types.Finding {
	return d.findings
}

func TestEngine_Run_EmptyData(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&testDetector{
		BaseDetector: NewBaseDetector("TEST_1", CategoryAccounts),
		findings: []types.Finding{{
			Type:     "TEST_1",
			Severity: types.SeverityLow,
			Category: "accounts",
			Title:    "Test Finding",
			Count:    0, // Zero count = filtered out
		}},
	})

	provider := &testProvider{}
	engine := NewEngine(registry, provider)

	result, err := engine.Run(context.Background(), RunOptions{})
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 100, result.Score) // No findings = perfect score
	assert.Len(t, result.Findings, 0) // Zero-count findings filtered
}

func TestEngine_Run_WithFindings(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&testDetector{
		BaseDetector: NewBaseDetector("HIGH_FINDING", CategoryAccounts),
		findings: []types.Finding{{
			Type:     "HIGH_FINDING",
			Severity: types.SeverityHigh,
			Category: "accounts",
			Title:    "High Severity Finding",
			Count:    5,
		}},
	})
	registry.Register(&testDetector{
		BaseDetector: NewBaseDetector("LOW_FINDING", CategoryGroups),
		findings: []types.Finding{{
			Type:     "LOW_FINDING",
			Severity: types.SeverityLow,
			Category: "groups",
			Title:    "Low Severity Finding",
			Count:    3,
		}},
	})

	provider := &testProvider{
		users: []types.User{
			{SAMAccountName: "user1"},
			{SAMAccountName: "user2"},
		},
	}
	engine := NewEngine(registry, provider)

	result, err := engine.Run(context.Background(), RunOptions{})
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Findings, 2)
	assert.Less(t, result.Score, 100) // Has findings, score < 100
	assert.Equal(t, 2, result.Statistics.UsersScanned)
}

func TestEngine_Run_FilterByCategory(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&testDetector{
		BaseDetector: NewBaseDetector("ACCOUNTS_1", CategoryAccounts),
		findings: []types.Finding{{
			Type:     "ACCOUNTS_1",
			Severity: types.SeverityHigh,
			Category: "accounts",
			Title:    "Accounts Finding",
			Count:    1,
		}},
	})
	registry.Register(&testDetector{
		BaseDetector: NewBaseDetector("GROUPS_1", CategoryGroups),
		findings: []types.Finding{{
			Type:     "GROUPS_1",
			Severity: types.SeverityHigh,
			Category: "groups",
			Title:    "Groups Finding",
			Count:    1,
		}},
	})

	provider := &testProvider{}
	engine := NewEngine(registry, provider)

	// Run only accounts category
	result, err := engine.Run(context.Background(), RunOptions{
		Categories: []DetectorCategory{CategoryAccounts},
	})
	require.NoError(t, err)
	assert.Len(t, result.Findings, 1)
	assert.Equal(t, "ACCOUNTS_1", result.Findings[0].Type)
}

func TestEngine_Run_FilterByID(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&testDetector{
		BaseDetector: NewBaseDetector("DETECTOR_A", CategoryAccounts),
		findings: []types.Finding{{
			Type:  "DETECTOR_A",
			Count: 1,
		}},
	})
	registry.Register(&testDetector{
		BaseDetector: NewBaseDetector("DETECTOR_B", CategoryAccounts),
		findings: []types.Finding{{
			Type:  "DETECTOR_B",
			Count: 1,
		}},
	})

	provider := &testProvider{}
	engine := NewEngine(registry, provider)

	// Run only specific detector
	result, err := engine.Run(context.Background(), RunOptions{
		DetectorIDs: []string{"DETECTOR_A"},
	})
	require.NoError(t, err)
	assert.Len(t, result.Findings, 1)
	assert.Equal(t, "DETECTOR_A", result.Findings[0].Type)
}

func TestEngine_Run_Parallel(t *testing.T) {
	registry := NewRegistry()

	// Add multiple detectors
	for i := 0; i < 10; i++ {
		id := "TEST_" + string(rune('A'+i))
		registry.Register(&testDetector{
			BaseDetector: NewBaseDetector(id, CategoryAccounts),
			findings: []types.Finding{{
				Type:  id,
				Count: 1,
			}},
		})
	}

	provider := &testProvider{}
	engine := NewEngine(registry, provider)

	// Run in parallel
	result, err := engine.Run(context.Background(), RunOptions{
		Parallel: true,
	})
	require.NoError(t, err)
	assert.Len(t, result.Findings, 10)
}

func TestEngine_Run_Statistics(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&testDetector{
		BaseDetector: NewBaseDetector("CRIT", CategoryAccounts),
		findings: []types.Finding{{
			Type:     "CRIT",
			Severity: types.SeverityCritical,
			Category: "accounts",
			Count:    2,
		}},
	})
	registry.Register(&testDetector{
		BaseDetector: NewBaseDetector("HIGH", CategoryGroups),
		findings: []types.Finding{{
			Type:     "HIGH",
			Severity: types.SeverityHigh,
			Category: "groups",
			Count:    3,
		}},
	})

	provider := &testProvider{
		users:     make([]types.User, 100),
		groups:    make([]types.Group, 50),
		computers: make([]types.Computer, 25),
	}
	engine := NewEngine(registry, provider)

	result, err := engine.Run(context.Background(), RunOptions{})
	require.NoError(t, err)

	assert.Equal(t, 2, result.Statistics.TotalFindings)
	assert.Equal(t, 100, result.Statistics.UsersScanned)
	assert.Equal(t, 50, result.Statistics.GroupsScanned)
	assert.Equal(t, 25, result.Statistics.ComputersScanned)
	assert.Equal(t, 1, result.Statistics.BySeverity[types.SeverityCritical])
	assert.Equal(t, 1, result.Statistics.BySeverity[types.SeverityHigh])
	assert.Equal(t, 1, result.Statistics.ByCategory["accounts"])
	assert.Equal(t, 1, result.Statistics.ByCategory["groups"])
}

func TestEngine_Run_Duration(t *testing.T) {
	registry := NewRegistry()
	provider := &testProvider{}
	engine := NewEngine(registry, provider)

	result, err := engine.Run(context.Background(), RunOptions{})
	require.NoError(t, err)

	assert.True(t, result.Duration >= 0)
	assert.False(t, result.Timestamp.IsZero())
}

func TestEngine_Run_WithStaleUsers(t *testing.T) {
	// This tests integration with real detectors
	registry := NewRegistry()

	// Register a stale account detector manually for testing
	registry.Register(&testDetector{
		BaseDetector: NewBaseDetector("STALE_ACCOUNT", CategoryAccounts),
		findings: []types.Finding{{
			Type:     "STALE_ACCOUNT",
			Severity: types.SeverityHigh,
			Category: "accounts",
			Title:    "Stale Account",
			Count:    2,
		}},
	})

	provider := &testProvider{
		users: []types.User{
			{SAMAccountName: "active", LastLogon: time.Now()},
			{SAMAccountName: "stale1", LastLogon: time.Now().AddDate(-1, 0, 0)},
			{SAMAccountName: "stale2", LastLogon: time.Now().AddDate(-1, 0, 0)},
		},
	}

	engine := NewEngine(registry, provider)
	result, err := engine.Run(context.Background(), RunOptions{})
	require.NoError(t, err)

	assert.Len(t, result.Findings, 1)
	assert.Equal(t, "STALE_ACCOUNT", result.Findings[0].Type)
	assert.Equal(t, 2, result.Findings[0].Count)
}
