import { Request, Response, NextFunction } from 'express';
import { TokenService } from '../../services/auth/token.service';
import { logger } from '../../utils/logger';
import {
  TokenExpiredError,
  TokenRevokedError,
  UsageLimitExceededError,
  TokenNotFoundError,
  InvalidSignatureError,
  InvalidTokenError,
} from '../../services/auth/errors';

/**
 * Authentication Middleware
 *
 * Validates JWT tokens from Authorization header and enforces usage quotas.
 *
 * Features:
 * - Extracts token from Authorization: Bearer <token> header
 * - Validates JWT signature and constraints
 * - Increments usage count on successful authentication
 * - Attaches token info to request object
 * - Returns appropriate error responses (401/403)
 *
 * Task 3: Authentication Middleware (Story 1.4)
 */

/**
 * Extended Request interface with token information
 */
export interface AuthenticatedRequest extends Request {
  token?: {
    jti: string;
    iat: number;
    exp: number;
    maxUses: number;
  };
}

/**
 * Create authentication middleware with token service
 *
 * Usage:
 * ```typescript
 * router.post('/protected', authenticate(tokenService), controller.method);
 * ```
 *
 * @param tokenService TokenService instance for validation
 * @returns Express middleware function
 */
export const authenticate = (tokenService: TokenService) => {
  return async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
    try {
      // 1. Extract token from Authorization header (Bearer <token>)
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        logger.warn('Authentication failed: missing or invalid Authorization header', {
          path: req.path,
          method: req.method,
        });
        res.status(401).json({
          success: false,
          error: {
            code: 'AUTHENTICATION_FAILED',
            message: 'Missing or invalid Authorization header',
          },
        });
        return;
      }

      const token = authHeader.substring(7); // Remove 'Bearer '

      // 2. Validate token
      const payload = await tokenService.validate(token);

      // 3. Increment usage count
      await tokenService.incrementUsage(payload.jti);

      // 4. Attach token info to request
      req.token = {
        jti: payload.jti,
        iat: payload.iat,
        exp: payload.exp,
        maxUses: payload.maxUses,
      };

      // 5. Log successful authentication
      logger.debug('Request authenticated', {
        jti: payload.jti,
        path: req.path,
        method: req.method,
      });

      next();
    } catch (error) {
      // Handle authentication errors with specific error codes

      if (error instanceof TokenExpiredError) {
        logger.warn('Authentication failed: token expired', {
          path: req.path,
          method: req.method,
        });
        res.status(401).json({
          success: false,
          error: {
            code: 'TOKEN_EXPIRED',
            message: 'Token has expired',
          },
        });
        return;
      }

      if (error instanceof TokenRevokedError) {
        logger.warn('Authentication failed: token revoked', {
          path: req.path,
          method: req.method,
        });
        res.status(401).json({
          success: false,
          error: {
            code: 'TOKEN_REVOKED',
            message: 'Token has been revoked',
          },
        });
        return;
      }

      if (error instanceof UsageLimitExceededError) {
        logger.warn('Authentication failed: usage limit exceeded', {
          path: req.path,
          method: req.method,
        });
        res.status(403).json({
          success: false,
          error: {
            code: 'USAGE_LIMIT_EXCEEDED',
            message: 'Token usage limit exceeded',
          },
        });
        return;
      }

      if (error instanceof TokenNotFoundError) {
        logger.warn('Authentication failed: token not found', {
          path: req.path,
          method: req.method,
        });
        res.status(401).json({
          success: false,
          error: {
            code: 'AUTHENTICATION_FAILED',
            message: 'Invalid token',
          },
        });
        return;
      }

      if (error instanceof InvalidSignatureError) {
        logger.warn('Authentication failed: invalid signature', {
          path: req.path,
          method: req.method,
        });
        res.status(401).json({
          success: false,
          error: {
            code: 'AUTHENTICATION_FAILED',
            message: 'Invalid token signature',
          },
        });
        return;
      }

      if (error instanceof InvalidTokenError) {
        logger.warn('Authentication failed: invalid token', {
          path: req.path,
          method: req.method,
        });
        res.status(401).json({
          success: false,
          error: {
            code: 'AUTHENTICATION_FAILED',
            message: 'Invalid token',
          },
        });
        return;
      }

      // Generic error for unexpected cases
      logger.error('Authentication failed: unexpected error', {
        path: req.path,
        method: req.method,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      res.status(401).json({
        success: false,
        error: {
          code: 'AUTHENTICATION_FAILED',
          message: 'Authentication failed',
        },
      });
    }
  };
};
