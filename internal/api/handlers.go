package api

import (
	"net/http"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// healthHandler returns server health status
func (s *Server) healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "ok",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"version":   "2.1.1",
	})
}

// AuditRequest is the request body for running an audit
type AuditRequest struct {
	IncludeDetails bool `json:"includeDetails"`
	MaxUsers       int  `json:"maxUsers"`
	MaxGroups      int  `json:"maxGroups"`
	MaxComputers   int  `json:"maxComputers"`
	Async          bool `json:"async"`
}

// runAuditHandler executes an AD audit
func (s *Server) runAuditHandler(c *gin.Context) {
	var req AuditRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// If no body provided, use defaults
		req = AuditRequest{}
	}

	// Check for async query param
	if c.Query("async") == "true" {
		req.Async = true
	}

	// Check if provider is available
	if s.engine == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":   "provider_unavailable",
			"message": "No provider configured",
		})
		return
	}

	opts := audit.RunOptions{
		IncludeDetails: req.IncludeDetails,
		MaxUsers:       req.MaxUsers,
		MaxGroups:      req.MaxGroups,
		MaxComputers:   req.MaxComputers,
		Parallel:       true,
	}

	// Async execution
	if req.Async {
		job := s.jobStore.Create("ad_audit")

		go func() {
			result, err := s.engine.Run(c.Request.Context(), opts)
			if err != nil {
				s.jobStore.Fail(job.ID, err)
				s.logger.Error("Async audit failed", zap.Error(err))
				return
			}
			s.jobStore.Complete(job.ID, result)
		}()

		c.JSON(http.StatusAccepted, gin.H{
			"jobId":   job.ID,
			"status":  "running",
			"message": "Audit started in background",
		})
		return
	}

	// Sync execution
	result, err := s.engine.Run(c.Request.Context(), opts)
	if err != nil {
		s.logger.Error("Audit failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "audit_failed",
			"message": err.Error(),
		})
		return
	}

	// Convert to TypeScript-compatible format
	response := types.ConvertToTSFormat(result, s.config.LDAP.URL, s.config.LDAP.BaseDN, req.IncludeDetails)
	c.JSON(http.StatusOK, response)
}

// auditStatusHandler returns current audit status
func (s *Server) auditStatusHandler(c *gin.Context) {
	// Return current provider status
	if s.manager == nil {
		c.JSON(http.StatusOK, gin.H{
			"status":   "not_configured",
			"provider": nil,
		})
		return
	}

	provider := s.manager.Primary()
	if provider == nil {
		c.JSON(http.StatusOK, gin.H{
			"status":   "not_configured",
			"provider": nil,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":   "ready",
		"provider": string(provider.Type()),
	})
}

// listJobsHandler returns all jobs
func (s *Server) listJobsHandler(c *gin.Context) {
	jobs := s.jobStore.List()
	c.JSON(http.StatusOK, gin.H{
		"jobs": jobs,
	})
}

// getJobHandler returns a specific job
func (s *Server) getJobHandler(c *gin.Context) {
	id := c.Param("id")

	job, ok := s.jobStore.Get(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "not_found",
			"message": "Job not found",
		})
		return
	}

	response := gin.H{
		"id":        job.ID,
		"type":      job.Type,
		"status":    job.Status,
		"createdAt": job.CreatedAt,
	}

	if job.CompletedAt != nil {
		response["completedAt"] = job.CompletedAt
	}

	if job.Error != "" {
		response["error"] = job.Error
	}

	if job.Result != nil {
		// Convert result to TypeScript-compatible format
		response["result"] = types.ConvertToTSFormat(job.Result, s.config.LDAP.URL, s.config.LDAP.BaseDN, false)
	}

	c.JSON(http.StatusOK, response)
}

// providersInfoHandler returns available providers
func (s *Server) providersInfoHandler(c *gin.Context) {
	if s.manager == nil {
		c.JSON(http.StatusOK, gin.H{
			"providers": []interface{}{},
		})
		return
	}

	providers := s.manager.All()
	infos := make([]gin.H, 0, len(providers))

	for _, p := range providers {
		infos = append(infos, gin.H{
			"type":      string(p.Type()),
			"connected": p.IsConnected(),
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"providers": infos,
	})
}

// TokenRequest is the request body for creating a token
type TokenRequest struct {
	Service  string `json:"service"`
	Duration string `json:"duration"` // e.g., "24h", "7d", "30d"
	MaxUses  int    `json:"maxUses"`
}

// createTokenHandler creates a new JWT token
func (s *Server) createTokenHandler(c *gin.Context) {
	var req TokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid_request",
			"message": "Invalid request body",
		})
		return
	}

	// Parse duration
	duration := 24 * time.Hour // default
	if req.Duration != "" {
		d, err := time.ParseDuration(req.Duration)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "invalid_duration",
				"message": "Invalid duration format",
			})
			return
		}
		duration = d
	}

	// Generate token
	token, err := types.GenerateToken(
		s.config.Auth.PrivateKey,
		"system",
		req.Service,
		duration,
		req.MaxUses,
	)
	if err != nil {
		s.logger.Error("Failed to generate token", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "token_generation_failed",
			"message": "Failed to generate token",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":     token,
		"expiresAt": time.Now().Add(duration).Format(time.RFC3339),
	})
}

// tokenInfoHandler returns info about the current token
func (s *Server) tokenInfoHandler(c *gin.Context) {
	claims, exists := c.Get("claims")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "unauthorized",
			"message": "No token claims found",
		})
		return
	}

	tokenClaims := claims.(*types.TokenClaims)

	c.JSON(http.StatusOK, gin.H{
		"subject":   tokenClaims.Subject,
		"service":   tokenClaims.Service,
		"issuedAt":  tokenClaims.IssuedAt.Time.Format(time.RFC3339),
		"expiresAt": tokenClaims.ExpiresAt.Time.Format(time.RFC3339),
		"jti":       tokenClaims.ID,
	})
}

// validateTokenHandler validates a token
func (s *Server) validateTokenHandler(c *gin.Context) {
	var req struct {
		Token string `json:"token"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Token == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid_request",
			"message": "Token is required",
		})
		return
	}

	claims, err := types.ValidateToken(s.config.Auth.PublicKey, req.Token)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"valid":   false,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"valid":     true,
		"subject":   claims.Subject,
		"service":   claims.Service,
		"expiresAt": claims.ExpiresAt.Time.Format(time.RFC3339),
	})
}
