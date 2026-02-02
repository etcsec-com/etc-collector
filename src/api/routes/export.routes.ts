import { Router, Request, Response, NextFunction } from 'express';
import { ExportController } from '../controllers/export.controller';
import { validate } from '../middlewares/validate';
import { authenticate } from '../middlewares/authenticate';
import { exportRequestSchema } from '../validators/audit.schemas';
import { TokenService } from '../../services/auth/token.service';

/**
 * Export routes
 * POST /api/v1/export/ad - Export AD audit results
 * POST /api/v1/export/azure - Export Azure audit results
 */
export const createExportRoutes = (controller: ExportController, tokenService: TokenService): Router => {
  const router = Router();
  const authMiddleware = authenticate(tokenService);

  // AD export
  router.post(
    '/ad',
    authMiddleware,
    validate(exportRequestSchema),
    (req: Request, res: Response, next: NextFunction) => controller.exportADAudit(req, res, next)
  );

  // Azure export
  router.post(
    '/azure',
    authMiddleware,
    validate(exportRequestSchema),
    (req: Request, res: Response, next: NextFunction) => controller.exportAzureAudit(req, res, next)
  );

  return router;
};
