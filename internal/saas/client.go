// Package saas implements the SaaS API client for cloud integration
package saas

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/etcsec-com/etc-collector/internal/logger"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Client is the SaaS API client
type Client struct {
	baseURL    string
	httpClient *http.Client
	token      string
	logger     *logger.Logger
}

// ClientOption is a functional option for Client
type ClientOption func(*Client)

// WithHTTPClient sets a custom HTTP client
func WithHTTPClient(client *http.Client) ClientOption {
	return func(c *Client) {
		c.httpClient = client
	}
}

// WithLogger sets a custom logger
func WithLogger(l *logger.Logger) ClientOption {
	return func(c *Client) {
		c.logger = l
	}
}

// NewClient creates a new SaaS API client
func NewClient(baseURL, token string, opts ...ClientOption) *Client {
	c := &Client{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger.Global(),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// SetToken updates the authentication token
func (c *Client) SetToken(token string) {
	c.token = token
}

// doRequest performs an HTTP request with authentication
func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	return c.httpClient.Do(req)
}

// HealthCheck checks if the SaaS API is reachable
func (c *Client) HealthCheck(ctx context.Context) error {
	resp, err := c.doRequest(ctx, http.MethodGet, "/health", nil)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check returned status %d", resp.StatusCode)
	}

	return nil
}

// EnrollRequest is the request body for enrollment
type EnrollRequest struct {
	CollectorID   string `json:"collectorId"`
	CollectorName string `json:"collectorName"`
	Hostname      string `json:"hostname"`
	Platform      string `json:"platform"`
	Version       string `json:"version"`
}

// EnrollResponse is the response from enrollment
type EnrollResponse struct {
	Token        string `json:"token"`
	CollectorID  string `json:"collectorId"`
	RefreshToken string `json:"refreshToken,omitempty"`
	ExpiresAt    string `json:"expiresAt"`
}

// Enroll registers this collector with the SaaS platform
func (c *Client) Enroll(ctx context.Context, enrollCode string, req EnrollRequest) (*EnrollResponse, error) {
	path := fmt.Sprintf("/api/v1/collectors/enroll?code=%s", enrollCode)

	resp, err := c.doRequest(ctx, http.MethodPost, path, req)
	if err != nil {
		return nil, fmt.Errorf("enrollment request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("enrollment failed with status %d: %s", resp.StatusCode, string(body))
	}

	var enrollResp EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&enrollResp); err != nil {
		return nil, fmt.Errorf("decode enrollment response: %w", err)
	}

	// Store the token
	c.token = enrollResp.Token

	return &enrollResp, nil
}

// ReportResult sends an audit result to the SaaS platform
func (c *Client) ReportResult(ctx context.Context, result *types.AuditResult) error {
	resp, err := c.doRequest(ctx, http.MethodPost, "/api/v1/collectors/report", result)
	if err != nil {
		return fmt.Errorf("report request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("report failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// Heartbeat sends a heartbeat to the SaaS platform
func (c *Client) Heartbeat(ctx context.Context, status *CollectorStatus) error {
	resp, err := c.doRequest(ctx, http.MethodPost, "/api/v1/collectors/heartbeat", status)
	if err != nil {
		return fmt.Errorf("heartbeat request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("heartbeat returned status %d", resp.StatusCode)
	}

	return nil
}

// CollectorStatus represents the status sent in heartbeats
type CollectorStatus struct {
	CollectorID     string    `json:"collectorId"`
	Status          string    `json:"status"` // "online", "busy", "offline"
	LastAudit       time.Time `json:"lastAudit,omitempty"`
	CurrentActivity string    `json:"currentActivity,omitempty"`
	Version         string    `json:"version"`
	Uptime          int64     `json:"uptime"` // seconds
}

// GetConfig fetches the collector configuration from SaaS
func (c *Client) GetConfig(ctx context.Context) (*CollectorConfig, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, "/api/v1/collectors/config", nil)
	if err != nil {
		return nil, fmt.Errorf("get config failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get config returned status %d", resp.StatusCode)
	}

	var config CollectorConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}

	return &config, nil
}

// CollectorConfig represents remote configuration from SaaS
type CollectorConfig struct {
	AuditInterval    int      `json:"auditInterval"`    // minutes
	IncludeDetails   bool     `json:"includeDetails"`
	EnabledDetectors []string `json:"enabledDetectors"` // empty = all
}

// RefreshToken refreshes the authentication token
func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (*EnrollResponse, error) {
	req := map[string]string{"refreshToken": refreshToken}

	resp, err := c.doRequest(ctx, http.MethodPost, "/api/v1/collectors/refresh", req)
	if err != nil {
		return nil, fmt.Errorf("refresh token failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("refresh token returned status %d", resp.StatusCode)
	}

	var tokenResp EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("decode refresh response: %w", err)
	}

	c.token = tokenResp.Token
	return &tokenResp, nil
}
