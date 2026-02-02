import { Request, Response } from 'express';
import { version } from '../../../package.json';

/**
 * Health check controller
 */
export class HealthController {
  async checkHealth(_req: Request, res: Response): Promise<void> {
    res.json({
      success: true,
      status: 'healthy',
      timestamp: new Date().toISOString(),
      version,
    });
  }
}
