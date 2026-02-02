import { Request, Response, NextFunction } from 'express';
import { TokenService } from '../../services/auth/token.service';
import type { Logger } from 'winston';
import { logger } from '../../utils/logger';
import { JWTConfig } from '../../types/config.types';

/**
 * AuthController
 *
 * Handles JWT token management endpoints: generation, validation, revocation, and info.
 *
 * Endpoints:
 * - POST /api/v1/auth/token - Generate new token
 * - POST /api/v1/auth/validate - Validate token without incrementing usage
 * - POST /api/v1/auth/revoke - Revoke token by jti
 * - GET /api/v1/auth/tokens - List all tokens
 * - GET /api/v1/auth/tokens/:jti - Get token info
 *
 * Task 4: Auth Controller with Token Endpoints (Story 1.4)
 */
export class AuthController {
  private logger: Logger;

  constructor(
    private tokenService: TokenService,
    private jwtConfig: JWTConfig
  ) {
    this.logger = logger;
  }

  /**
   * POST /api/v1/auth/token
   * Generate a new JWT token with usage quotas
   *
   * Request Body:
   * - expiresIn: string (optional, default from config) - e.g., '1h', '7d', '30d'
   * - maxUses: number (optional, default from TOKEN_MAX_USES config) - 0 = unlimited
   * - metadata: object (optional) - arbitrary metadata
   *
   * Response:
   * - 201: Token generated successfully
   * - 400: Invalid request
   * - 500: Server error
   */
  async generateToken(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { expiresIn, maxUses, metadata } = req.body;

      // Use config defaults if not provided
      const effectiveExpiresIn = expiresIn || this.jwtConfig.tokenExpiry;
      const effectiveMaxUses = maxUses !== undefined ? maxUses : this.jwtConfig.tokenMaxUses;

      const token = await this.tokenService.generate({
        expiresIn: effectiveExpiresIn,
        maxUses: effectiveMaxUses,
        metadata,
      });

      this.logger.info('Token generated via API', {
        expiresIn: effectiveExpiresIn,
        maxUses: effectiveMaxUses,
        hasMetadata: !!metadata,
      });

      res.status(201).json({
        success: true,
        token,
        expiresIn: effectiveExpiresIn,
        maxUses: effectiveMaxUses,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * POST /api/v1/auth/validate
   * Validate a JWT token without incrementing usage
   *
   * This endpoint checks token validity but does NOT increment usage count.
   * Use this for validation checks that shouldn't consume usage quota.
   *
   * Request Body:
   * - token: string - JWT token to validate
   *
   * Response:
   * - 200: Validation result (always 200, even if invalid)
   *   - valid: true - Token is valid
   *   - valid: false - Token is invalid (includes error message)
   */
  async validateToken(req: Request, res: Response, _next: NextFunction): Promise<void> {
    try {
      const { token } = req.body;

      // Attempt to validate token
      const payload = await this.tokenService.validate(token);

      // Token is valid
      res.json({
        success: true,
        valid: true,
        payload: {
          jti: payload.jti,
          iat: payload.iat,
          exp: payload.exp,
          maxUses: payload.maxUses,
        },
      });
    } catch (error) {
      // Token validation failed, but still return 200 with valid: false
      // This allows clients to distinguish between validation failure and server errors
      res.json({
        success: true,
        valid: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }

  /**
   * POST /api/v1/auth/revoke
   * Revoke a token by jti
   *
   * Request Body:
   * - jti: string - JWT ID to revoke
   * - reason: string (optional) - Revocation reason
   *
   * Response:
   * - 200: Token revoked successfully
   * - 404: Token not found
   * - 500: Server error
   */
  async revokeToken(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { jti, reason } = req.body;
      const revokedBy = 'system'; // TODO: Get from authenticated user in future

      await this.tokenService.revoke(jti, revokedBy, reason || 'Manual revocation');

      this.logger.info('Token revoked via API', { jti, reason });

      res.json({
        success: true,
        message: 'Token revoked successfully',
        jti,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * GET /api/v1/auth/tokens
   * List all tokens (including expired and revoked)
   *
   * Response:
   * - 200: List of all tokens
   * - 500: Server error
   */
  async listTokens(_req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const tokens = await this.tokenService.listAll();

      res.json({
        success: true,
        count: tokens.length,
        tokens,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * GET /api/v1/auth/tokens/:jti
   * Get detailed information about a specific token
   *
   * URL Parameters:
   * - jti: string - JWT ID
   *
   * Response:
   * - 200: Token information
   * - 404: Token not found
   * - 500: Server error
   */
  async getTokenInfo(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const jti = req.params['jti'];
      if (!jti || Array.isArray(jti)) {
        res.status(400).json({
          success: false,
          error: { code: 'BAD_REQUEST', message: 'jti parameter is required and must be a string' },
        });
        return;
      }

      const info = await this.tokenService.getInfo(jti);

      res.json({
        success: true,
        token: info,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * GET /api/v1/auth/token/info
   * Get detailed information about the current token from Authorization header
   *
   * This endpoint requires TOKEN_INFO_ENABLED=true.
   * Returns full token details including usage stats.
   *
   * Response:
   * - 200: Token information
   * - 401: No token provided
   * - 500: Server error
   */
  async getCurrentTokenInfo(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      // Extract token from Authorization header
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({
          success: false,
          error: { code: 'UNAUTHORIZED', message: 'No token provided in Authorization header' },
        });
        return;
      }

      const token = authHeader.substring(7);

      // Validate token and get payload
      const payload = await this.tokenService.validate(token);

      // Get full token info from database
      const info = await this.tokenService.getInfo(payload.jti);

      res.json({
        success: true,
        token: {
          jti: info.jti,
          createdAt: info.created_at,
          expiresAt: info.expires_at,
          maxUses: info.max_uses,
          usageCount: info.used_count,
          remainingUses: info.max_uses === 0 ? 'unlimited' : info.remaining_uses,
          revoked: info.revoked,
          revokedAt: info.revoked_at,
          revokedReason: info.revoked_reason,
        },
      });
    } catch (error) {
      next(error);
    }
  }
}
