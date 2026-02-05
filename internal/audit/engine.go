package audit

import (
	"context"
	"sync"
	"time"

	"github.com/etcsec-com/etc-collector/internal/providers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Engine orchestrates the audit process
type Engine struct {
	registry *Registry
	provider providers.Provider
}

// NewEngine creates a new audit engine
func NewEngine(registry *Registry, provider providers.Provider) *Engine {
	if registry == nil {
		registry = DefaultRegistry
	}
	return &Engine{
		registry: registry,
		provider: provider,
	}
}

// RunOptions configures the audit run
type RunOptions struct {
	// Categories to run (empty = all)
	Categories []DetectorCategory

	// Specific detector IDs to run (empty = all)
	DetectorIDs []string

	// Include affected entities in findings
	IncludeDetails bool

	// Max users/groups/computers to fetch (0 = all)
	MaxUsers     int
	MaxGroups    int
	MaxComputers int

	// Parallel execution
	Parallel bool
}

// Run executes the audit
func (e *Engine) Run(ctx context.Context, opts RunOptions) (*types.AuditResult, error) {
	startTime := time.Now()

	// Collect data from provider
	data, err := e.collectData(ctx, opts)
	if err != nil {
		return nil, err
	}

	// Get detectors to run
	detectors := e.selectDetectors(opts)

	// Run detectors
	var allFindings []types.Finding
	if opts.Parallel {
		allFindings = e.runParallel(ctx, detectors, data)
	} else {
		allFindings = e.runSequential(ctx, detectors, data)
	}

	// Filter out zero-count findings
	var findings []types.Finding
	for _, f := range allFindings {
		if f.Count > 0 {
			findings = append(findings, f)
		}
	}

	// Calculate statistics
	stats := e.calculateStats(findings, data)

	// Calculate score
	score := types.CalculateScore(findings)
	grade := types.CalculateGrade(score)

	// Build result
	result := &types.AuditResult{
		Timestamp:  startTime,
		Duration:   time.Since(startTime),
		Score:      score,
		Grade:      grade,
		Provider:   string(e.provider.Type()),
		Findings:   findings,
		Statistics: stats,
		Summary:    e.buildSummary(findings),
	}

	// Add domain info if available
	if data.DomainInfo != nil {
		result.Domain = data.DomainInfo.DomainName
	}

	return result, nil
}

// collectData fetches data from the provider
func (e *Engine) collectData(ctx context.Context, opts RunOptions) (*DetectorData, error) {
	data := &DetectorData{
		IncludeDetails: opts.IncludeDetails,
	}

	// Fetch users
	userOpts := providers.QueryOptions{MaxResults: opts.MaxUsers}
	users, err := e.provider.GetUsers(ctx, userOpts)
	if err != nil {
		return nil, err
	}
	data.Users = users

	// Fetch groups
	groupOpts := providers.QueryOptions{MaxResults: opts.MaxGroups}
	groups, err := e.provider.GetGroups(ctx, groupOpts)
	if err != nil {
		return nil, err
	}
	data.Groups = groups

	// Fetch computers
	computerOpts := providers.QueryOptions{MaxResults: opts.MaxComputers}
	computers, err := e.provider.GetComputers(ctx, computerOpts)
	if err != nil {
		return nil, err
	}
	data.Computers = computers

	// Fetch domain info
	domainInfo, err := e.provider.GetDomainInfo(ctx)
	if err != nil {
		// Non-fatal, continue without domain info
		domainInfo = nil
	}
	data.DomainInfo = domainInfo

	// Fetch GPOs if provider supports it
	if ldapProvider, ok := e.provider.(LDAPProvider); ok {
		gpos, _ := ldapProvider.GetGPOs(ctx, providers.QueryOptions{})
		data.GPOs = gpos

		// Collect GPO links from OUs and Sites
		gpoLinks, _ := ldapProvider.GetGPOLinks(ctx)
		data.GPOLinks = gpoLinks

		// Collect GPO ACLs
		var gpoDNs []string
		for _, gpo := range gpos {
			gpoDNs = append(gpoDNs, gpo.DN)
		}
		gpoAcls, _ := ldapProvider.GetGPOAcls(ctx, gpoDNs)
		data.GPOAcls = gpoAcls

		trusts, _ := ldapProvider.GetTrusts(ctx, providers.QueryOptions{})
		data.Trusts = trusts

		certs, _ := ldapProvider.GetCertTemplates(ctx, providers.QueryOptions{})
		data.CertTemplates = certs

		// Collect ACLs for all objects (users, groups, computers)
		// This enables permission-based detectors
		var objectDNs []string
		for _, u := range data.Users {
			objectDNs = append(objectDNs, u.DN)
		}
		for _, g := range data.Groups {
			objectDNs = append(objectDNs, g.DN)
		}
		for _, c := range data.Computers {
			objectDNs = append(objectDNs, c.DN)
		}

		// Also add critical system objects
		if data.DomainInfo != nil && data.DomainInfo.DomainDN != "" {
			baseDN := data.DomainInfo.DomainDN
			objectDNs = append(objectDNs, baseDN) // Domain root
			objectDNs = append(objectDNs, "CN=AdminSDHolder,CN=System,"+baseDN)
			objectDNs = append(objectDNs, "CN=Policies,CN=System,"+baseDN)
		}

		acls, _ := ldapProvider.GetACLs(ctx, objectDNs)
		data.ACLEntries = acls
	}

	return data, nil
}

// LDAPProvider is an extended provider interface for LDAP-specific queries
type LDAPProvider interface {
	providers.Provider
	GetGPOs(ctx context.Context, opts providers.QueryOptions) ([]types.GPO, error)
	GetGPOLinks(ctx context.Context) ([]GPOLink, error)
	GetGPOAcls(ctx context.Context, gpoDNs []string) ([]GPOAcl, error)
	GetTrusts(ctx context.Context, opts providers.QueryOptions) ([]types.Trust, error)
	GetCertTemplates(ctx context.Context, opts providers.QueryOptions) ([]types.CertTemplate, error)
	GetACLs(ctx context.Context, objectDNs []string) ([]types.ACLEntry, error)
}

// selectDetectors returns the detectors to run based on options
func (e *Engine) selectDetectors(opts RunOptions) []Detector {
	var detectors []Detector

	// If specific IDs provided, use those
	if len(opts.DetectorIDs) > 0 {
		for _, id := range opts.DetectorIDs {
			if d, ok := e.registry.Get(id); ok {
				detectors = append(detectors, d)
			}
		}
		return detectors
	}

	// If categories provided, filter by category
	if len(opts.Categories) > 0 {
		catSet := make(map[DetectorCategory]bool)
		for _, cat := range opts.Categories {
			catSet[cat] = true
		}
		for _, d := range e.registry.All() {
			if catSet[d.Category()] {
				detectors = append(detectors, d)
			}
		}
		return detectors
	}

	// Otherwise, return all detectors
	return e.registry.All()
}

// runSequential runs detectors one by one
func (e *Engine) runSequential(ctx context.Context, detectors []Detector, data *DetectorData) []types.Finding {
	var findings []types.Finding
	for _, d := range detectors {
		select {
		case <-ctx.Done():
			return findings
		default:
			results := d.Detect(ctx, data)
			findings = append(findings, results...)
		}
	}
	return findings
}

// runParallel runs detectors concurrently
func (e *Engine) runParallel(ctx context.Context, detectors []Detector, data *DetectorData) []types.Finding {
	var (
		mu       sync.Mutex
		findings []types.Finding
		wg       sync.WaitGroup
	)

	for _, d := range detectors {
		wg.Add(1)
		go func(detector Detector) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			default:
				results := detector.Detect(ctx, data)
				mu.Lock()
				findings = append(findings, results...)
				mu.Unlock()
			}
		}(d)
	}

	wg.Wait()
	return findings
}

// calculateStats calculates audit statistics
func (e *Engine) calculateStats(findings []types.Finding, data *DetectorData) *types.AuditStatistics {
	stats := types.NewAuditStatistics()
	stats.TotalFindings = len(findings)
	stats.UsersScanned = len(data.Users)
	stats.GroupsScanned = len(data.Groups)
	stats.ComputersScanned = len(data.Computers)

	for _, f := range findings {
		stats.BySeverity[f.Severity]++
		stats.ByCategory[f.Category]++
	}

	return stats
}

// buildSummary creates a summary of findings by type
func (e *Engine) buildSummary(findings []types.Finding) []types.FindingSummary {
	byType := make(map[string]*types.FindingSummary)

	for _, f := range findings {
		if _, ok := byType[f.Type]; !ok {
			byType[f.Type] = &types.FindingSummary{
				Type:     f.Type,
				Severity: f.Severity,
				Count:    0,
			}
		}
		byType[f.Type].Count += f.Count
	}

	var summary []types.FindingSummary
	for _, s := range byType {
		summary = append(summary, *s)
	}

	return summary
}
