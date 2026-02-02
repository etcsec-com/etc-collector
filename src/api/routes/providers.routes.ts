import { Router, Request, Response, NextFunction } from 'express';
import { ProvidersController } from '../controllers/providers.controller';
import { InfoEndpointsConfig } from '../../types/config.types';

/**
 * Providers routes
 * GET /api/v1/providers/info - Get all providers info (if PROVIDERS_INFO_ENABLED)
 */
export const createProvidersRoutes = (
  controller: ProvidersController,
  infoEndpointsConfig: InfoEndpointsConfig
): Router => {
  const router = Router();

  // Providers info endpoint (conditional - only if PROVIDERS_INFO_ENABLED)
  if (infoEndpointsConfig.providersInfoEnabled) {
    router.get(
      '/info',
      (req: Request, res: Response, next: NextFunction) => controller.getProvidersInfo(req, res, next)
    );
  }

  return router;
};
