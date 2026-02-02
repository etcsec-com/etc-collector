import { Router, Request, Response, NextFunction } from 'express';
import { AuthController } from '../controllers/auth.controller';
import { validate } from '../middlewares/validate';
import { authenticate } from '../middlewares/authenticate';
import {
  GenerateTokenSchema,
  ValidateTokenSchema,
  RevokeTokenSchema,
} from '../validators/auth.schemas';
import { TokenService } from '../../services/auth/token.service';
import { InfoEndpointsConfig } from '../../types/config.types';

/**
 * Authentication routes
 * POST /api/v1/auth/token - Generate JWT token
 * POST /api/v1/auth/validate - Validate token
 * POST /api/v1/auth/revoke - Revoke token
 * GET /api/v1/auth/tokens - List all tokens
 * GET /api/v1/auth/tokens/:jti - Get token info by jti
 * GET /api/v1/auth/token/info - Get current token info (if TOKEN_INFO_ENABLED)
 */
export const createAuthRoutes = (
  controller: AuthController,
  tokenService: TokenService,
  infoEndpointsConfig: InfoEndpointsConfig
): Router => {
  const router = Router();
  const authMiddleware = authenticate(tokenService);

  router.post(
    '/token',
    validate(GenerateTokenSchema),
    (req, res, next) => controller.generateToken(req, res, next)
  );

  router.post(
    '/validate',
    validate(ValidateTokenSchema),
    (req, res, next) => controller.validateToken(req, res, next)
  );

  router.post(
    '/revoke',
    authMiddleware,
    validate(RevokeTokenSchema),
    (req: Request, res: Response, next: NextFunction) => controller.revokeToken(req, res, next)
  );

  router.get(
    '/tokens',
    authMiddleware,
    (req: Request, res: Response, next: NextFunction) => controller.listTokens(req, res, next)
  );

  // Get token info by jti (always available)
  router.get(
    '/tokens/:jti',
    authMiddleware,
    (req: Request, res: Response, next: NextFunction) => controller.getTokenInfo(req, res, next)
  );

  // Current token info endpoint (conditional - only if TOKEN_INFO_ENABLED)
  if (infoEndpointsConfig.tokenInfoEnabled) {
    router.get(
      '/token/info',
      (req: Request, res: Response, next: NextFunction) => controller.getCurrentTokenInfo(req, res, next)
    );
  }

  return router;
};
