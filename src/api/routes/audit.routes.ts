import { Router, Request, Response, NextFunction } from 'express';
import { AuditController } from '../controllers/audit.controller';
import { JobsController } from '../controllers/jobs.controller';
import { validate } from '../middlewares/validate';
import { authenticate } from '../middlewares/authenticate';
import { auditLimiter } from '../middlewares/rateLimit';
import { auditRequestSchema } from '../validators/audit.schemas';
import { TokenService } from '../../services/auth/token.service';

/**
 * Audit routes
 * POST /api/v1/audit/ad - Run AD audit (sync or async with ?async=true)
 * GET /api/v1/audit/ad/status - Check LDAP connection
 * POST /api/v1/audit/azure - Run Azure audit
 * GET /api/v1/audit/azure/status - Check Graph connection
 * GET /api/v1/audit/jobs - List all jobs
 * GET /api/v1/audit/jobs/:jobId - Get job status/progress
 * DELETE /api/v1/audit/jobs/:jobId - Delete/cancel a job
 */
export const createAuditRoutes = (controller: AuditController, tokenService: TokenService): Router => {
  const router = Router();
  const authMiddleware = authenticate(tokenService);
  const jobsController = new JobsController();

  // AD endpoints
  router.post(
    '/ad',
    authMiddleware,
    auditLimiter,
    validate(auditRequestSchema),
    (req: Request, res: Response, next: NextFunction) => controller.runADAudit(req, res, next)
  );

  router.get(
    '/ad/status',
    authMiddleware,
    (req: Request, res: Response, next: NextFunction) => controller.getADStatus(req, res, next)
  );

  // Azure endpoints
  router.post(
    '/azure',
    authMiddleware,
    auditLimiter,
    validate(auditRequestSchema),
    (req: Request, res: Response, next: NextFunction) => controller.runAzureAudit(req, res, next)
  );

  router.get(
    '/azure/status',
    authMiddleware,
    (req: Request, res: Response, next: NextFunction) => controller.getAzureStatus(req, res, next)
  );

  // Jobs endpoints (for async audit polling)
  router.get(
    '/jobs',
    authMiddleware,
    (req: Request, res: Response, next: NextFunction) => jobsController.listJobs(req, res, next)
  );

  router.get(
    '/jobs/:jobId',
    authMiddleware,
    (req: Request<{ jobId: string }>, res: Response, next: NextFunction) =>
      jobsController.getJobStatus(req, res, next)
  );

  router.delete(
    '/jobs/:jobId',
    authMiddleware,
    (req: Request<{ jobId: string }>, res: Response, next: NextFunction) =>
      jobsController.deleteJob(req, res, next)
  );

  return router;
};
