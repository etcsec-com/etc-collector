package api

import (
	"net/http"
	"strings"

	"github.com/etcsec-com/etc-collector/pkg/types"
	"github.com/gin-gonic/gin"
)

// authMiddleware validates JWT tokens
func (s *Server) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "Authorization header required",
			})
			return
		}

		// Extract token from "Bearer <token>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "Invalid authorization header format",
			})
			return
		}

		token := parts[1]

		// Validate token
		claims, err := types.ValidateToken(s.config.Auth.PublicKey, token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "Invalid or expired token",
			})
			return
		}

		// Store claims in context
		c.Set("claims", claims)
		c.Set("token", token)

		c.Next()
	}
}

// rateLimitMiddleware implements rate limiting (placeholder)
func (s *Server) rateLimitMiddleware() gin.HandlerFunc {
	// TODO: Implement proper rate limiting with token bucket or sliding window
	return func(c *gin.Context) {
		c.Next()
	}
}
