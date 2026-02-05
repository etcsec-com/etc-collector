// Package api implements the REST API server
package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/config"
	"github.com/etcsec-com/etc-collector/internal/logger"
	"github.com/etcsec-com/etc-collector/internal/providers"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Server is the HTTP API server
type Server struct {
	config   *config.Config
	router   *gin.Engine
	server   *http.Server
	manager  *providers.Manager
	engine   *audit.Engine
	logger   *zap.Logger
	jobStore *JobStore
}

// NewServer creates a new API server
func NewServer(cfg *config.Config, manager *providers.Manager) *Server {
	// Set gin mode based on environment
	if cfg.Server.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	s := &Server{
		config:   cfg,
		router:   router,
		manager:  manager,
		logger:   logger.Global().Zap(),
		jobStore: NewJobStore(),
	}

	// Create audit engine with default registry
	if manager != nil {
		provider := manager.Primary()
		if provider != nil {
			s.engine = audit.NewEngine(nil, provider)
		}
	}

	s.setupMiddleware()
	s.setupRoutes()

	return s
}

// setupMiddleware configures middleware
func (s *Server) setupMiddleware() {
	// Recovery middleware
	s.router.Use(gin.Recovery())

	// Logging middleware
	s.router.Use(s.loggingMiddleware())

	// CORS middleware
	s.router.Use(s.corsMiddleware())
}

// loggingMiddleware logs HTTP requests
func (s *Server) loggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path

		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()

		s.logger.Info("HTTP request",
			zap.String("method", c.Request.Method),
			zap.String("path", path),
			zap.Int("status", status),
			zap.Duration("latency", latency),
			zap.String("client_ip", c.ClientIP()),
		)
	}
}

// corsMiddleware handles CORS
func (s *Server) corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// setupRoutes configures API routes
func (s *Server) setupRoutes() {
	// Health check
	s.router.GET("/health", s.healthHandler)
	s.router.GET("/", s.healthHandler)

	// API v1 group
	v1 := s.router.Group("/api/v1")
	{
		// Auth endpoints
		auth := v1.Group("/auth")
		{
			auth.POST("/token", s.createTokenHandler)
			auth.GET("/token/info", s.authMiddleware(), s.tokenInfoHandler)
			auth.POST("/token/validate", s.validateTokenHandler)
		}

		// Audit endpoints
		audit := v1.Group("/audit")
		audit.Use(s.authMiddleware())
		{
			audit.POST("/ad", s.runAuditHandler)
			audit.GET("/ad/status", s.auditStatusHandler)
			audit.GET("/jobs", s.listJobsHandler)
			audit.GET("/jobs/:id", s.getJobHandler)
		}

		// Provider info endpoint
		info := v1.Group("/info")
		info.Use(s.authMiddleware())
		{
			info.GET("/providers", s.providersInfoHandler)
		}
	}
}

// Start starts the HTTP server
func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.config.Server.Host, s.config.Server.Port)

	s.server = &http.Server{
		Addr:         addr,
		Handler:      s.router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 300 * time.Second, // Long timeout for audits
		IdleTimeout:  60 * time.Second,
	}

	s.logger.Info("Starting API server", zap.String("address", addr))

	if s.config.Server.TLSEnabled {
		return s.server.ListenAndServeTLS(
			s.config.Server.TLSCertFile,
			s.config.Server.TLSKeyFile,
		)
	}

	return s.server.ListenAndServe()
}

// Shutdown gracefully stops the server
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("Shutting down API server")
	return s.server.Shutdown(ctx)
}

// Router returns the gin router (for testing)
func (s *Server) Router() *gin.Engine {
	return s.router
}
