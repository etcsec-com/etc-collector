import { Router } from 'express';
import { createHealthRoutes } from './health.routes';
import { createAuthRoutes } from './auth.routes';
import { createAuditRoutes } from './audit.routes';
import { createExportRoutes } from './export.routes';
import { createProvidersRoutes } from './providers.routes';
import { HealthController } from '../controllers/health.controller';
import { AuthController } from '../controllers/auth.controller';
import { AuditController } from '../controllers/audit.controller';
import { ExportController } from '../controllers/export.controller';
import { ProvidersController } from '../controllers/providers.controller';
import { TokenService } from '../../services/auth/token.service';
import { InfoEndpointsConfig } from '../../types/config.types';

/**
 * Main route aggregator
 * Mounts all API routes
 */
export const createRoutes = (
  healthController: HealthController,
  authController: AuthController,
  auditController: AuditController,
  exportController: ExportController,
  providersController: ProvidersController,
  tokenService: TokenService,
  infoEndpointsConfig: InfoEndpointsConfig
): Router => {
  const router = Router();

  // Mount health check at root
  router.use('/', createHealthRoutes(healthController));

  // Mount API v1 routes
  router.use('/api/v1/auth', createAuthRoutes(authController, tokenService, infoEndpointsConfig));
  router.use('/api/v1/audit', createAuditRoutes(auditController, tokenService));
  router.use('/api/v1/export', createExportRoutes(exportController, tokenService));
  router.use('/api/v1/providers', createProvidersRoutes(providersController, infoEndpointsConfig));

  return router;
};
