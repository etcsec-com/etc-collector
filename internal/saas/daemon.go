package saas

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/config"
	"github.com/etcsec-com/etc-collector/internal/logger"
	"github.com/etcsec-com/etc-collector/internal/providers"
)

// Daemon manages the background SaaS agent
type Daemon struct {
	config      *config.Config
	client      *Client
	credStore   *CredentialStore
	manager     *providers.Manager
	engine      *audit.Engine
	logger      *logger.Logger
	startTime   time.Time
	lastAudit   time.Time
	stopCh      chan struct{}
	wg          sync.WaitGroup
	mu          sync.Mutex
	running     bool
	currentTask string
}

// NewDaemon creates a new daemon instance
func NewDaemon(cfg *config.Config, manager *providers.Manager) (*Daemon, error) {
	credStore := NewCredentialStore(cfg.SaaS.DataDir)

	// Load existing credentials
	creds, err := credStore.Load()
	if err != nil {
		return nil, fmt.Errorf("load credentials: %w", err)
	}

	var client *Client
	if creds != nil {
		client = NewClient(creds.SaaSURL, creds.Token)
	} else {
		client = NewClient(cfg.SaaS.URL, "")
	}

	// Create audit engine
	var engine *audit.Engine
	if manager != nil && manager.Primary() != nil {
		engine = audit.NewEngine(nil, manager.Primary())
	}

	return &Daemon{
		config:    cfg,
		client:    client,
		credStore: credStore,
		manager:   manager,
		engine:    engine,
		logger:    logger.Global().Named("daemon"),
		stopCh:    make(chan struct{}),
	}, nil
}

// IsEnrolled returns true if the daemon is enrolled with SaaS
func (d *Daemon) IsEnrolled() bool {
	return d.credStore.Exists()
}

// Enroll enrolls this collector with the SaaS platform
func (d *Daemon) Enroll(ctx context.Context, enrollCode string) error {
	hostname, _ := os.Hostname()

	req := EnrollRequest{
		CollectorName: hostname,
		Hostname:      hostname,
		Platform:      runtime.GOOS + "/" + runtime.GOARCH,
		Version:       "2.0.0",
	}

	resp, err := d.client.Enroll(ctx, enrollCode, req)
	if err != nil {
		return fmt.Errorf("enrollment failed: %w", err)
	}

	// Store credentials
	creds := &Credentials{
		CollectorID:  resp.CollectorID,
		Token:        resp.Token,
		RefreshToken: resp.RefreshToken,
		SaaSURL:      d.config.SaaS.URL,
	}

	if err := d.credStore.Save(creds); err != nil {
		return fmt.Errorf("save credentials: %w", err)
	}

	d.logger.Info("Enrollment successful", "collectorId", resp.CollectorID)
	return nil
}

// Unenroll removes this collector from the SaaS platform
func (d *Daemon) Unenroll() error {
	return d.credStore.Delete()
}

// Start starts the daemon
func (d *Daemon) Start() error {
	d.mu.Lock()
	if d.running {
		d.mu.Unlock()
		return fmt.Errorf("daemon already running")
	}
	d.running = true
	d.startTime = time.Now()
	d.mu.Unlock()

	d.logger.Info("Starting daemon")

	// Start heartbeat goroutine
	d.wg.Add(1)
	go d.heartbeatLoop()

	// Start audit goroutine
	d.wg.Add(1)
	go d.auditLoop()

	return nil
}

// Stop stops the daemon
func (d *Daemon) Stop() error {
	d.mu.Lock()
	if !d.running {
		d.mu.Unlock()
		return nil
	}
	d.running = false
	d.mu.Unlock()

	d.logger.Info("Stopping daemon")
	close(d.stopCh)
	d.wg.Wait()

	return nil
}

// heartbeatLoop sends periodic heartbeats
func (d *Daemon) heartbeatLoop() {
	defer d.wg.Done()

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	// Send initial heartbeat
	d.sendHeartbeat()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.sendHeartbeat()
		}
	}
}

// sendHeartbeat sends a single heartbeat
func (d *Daemon) sendHeartbeat() {
	d.mu.Lock()
	status := &CollectorStatus{
		Status:          "online",
		LastAudit:       d.lastAudit,
		CurrentActivity: d.currentTask,
		Version:         "2.0.0",
		Uptime:          int64(time.Since(d.startTime).Seconds()),
	}
	d.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := d.client.Heartbeat(ctx, status); err != nil {
		d.logger.Warn("Heartbeat failed", "error", err)
	}
}

// auditLoop runs periodic audits
func (d *Daemon) auditLoop() {
	defer d.wg.Done()

	// Get initial config
	config, err := d.getRemoteConfig()
	if err != nil {
		d.logger.Warn("Failed to get remote config, using defaults", "error", err)
		config = &CollectorConfig{
			AuditInterval:  60, // 1 hour default
			IncludeDetails: false,
		}
	}

	ticker := time.NewTicker(time.Duration(config.AuditInterval) * time.Minute)
	defer ticker.Stop()

	// Run initial audit
	d.runAudit(config)

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			// Refresh config periodically
			newConfig, err := d.getRemoteConfig()
			if err == nil {
				config = newConfig
				// Update ticker interval if changed
				ticker.Reset(time.Duration(config.AuditInterval) * time.Minute)
			}
			d.runAudit(config)
		}
	}
}

// getRemoteConfig fetches configuration from SaaS
func (d *Daemon) getRemoteConfig() (*CollectorConfig, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return d.client.GetConfig(ctx)
}

// runAudit executes an audit and reports the result
func (d *Daemon) runAudit(config *CollectorConfig) {
	if d.engine == nil {
		d.logger.Warn("No audit engine configured, skipping audit")
		return
	}

	d.mu.Lock()
	d.currentTask = "Running audit"
	d.mu.Unlock()

	d.logger.Info("Starting scheduled audit")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	opts := audit.RunOptions{
		IncludeDetails: config.IncludeDetails,
		Parallel:       true,
	}

	result, err := d.engine.Run(ctx, opts)
	if err != nil {
		d.logger.Error("Audit failed", "error", err)
		d.mu.Lock()
		d.currentTask = ""
		d.mu.Unlock()
		return
	}

	d.mu.Lock()
	d.lastAudit = time.Now()
	d.currentTask = "Reporting results"
	d.mu.Unlock()

	// Report to SaaS
	reportCtx, reportCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer reportCancel()

	if err := d.client.ReportResult(reportCtx, result); err != nil {
		d.logger.Error("Failed to report audit result", "error", err)
	} else {
		d.logger.Info("Audit completed and reported",
			"score", result.Score,
			"grade", result.Grade,
			"findings", len(result.Findings),
		)
	}

	d.mu.Lock()
	d.currentTask = ""
	d.mu.Unlock()
}

// Status returns the current daemon status
func (d *Daemon) Status() *DaemonStatus {
	d.mu.Lock()
	defer d.mu.Unlock()

	return &DaemonStatus{
		Running:     d.running,
		Enrolled:    d.IsEnrolled(),
		Uptime:      time.Since(d.startTime),
		LastAudit:   d.lastAudit,
		CurrentTask: d.currentTask,
	}
}

// DaemonStatus represents the daemon's current state
type DaemonStatus struct {
	Running     bool          `json:"running"`
	Enrolled    bool          `json:"enrolled"`
	Uptime      time.Duration `json:"uptime"`
	LastAudit   time.Time     `json:"lastAudit"`
	CurrentTask string        `json:"currentTask,omitempty"`
}
