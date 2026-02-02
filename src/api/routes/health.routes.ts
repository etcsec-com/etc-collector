import { Router } from 'express';
import { HealthController } from '../controllers/health.controller';

/**
 * Health check routes
 * GET /health - Health check endpoint
 */
export const createHealthRoutes = (controller: HealthController): Router => {
  const router = Router();

  router.get('/health', (req, res) => controller.checkHealth(req, res));

  return router;
};
