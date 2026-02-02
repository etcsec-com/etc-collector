/**
 * Jobs Controller
 *
 * Handles async job status and management operations.
 *
 * Endpoints:
 * - GET /api/v1/audit/jobs/:jobId - Get job status and progress
 * - GET /api/v1/audit/jobs - List all jobs (optional status filter)
 * - DELETE /api/v1/audit/jobs/:jobId - Cancel/delete a job
 */

import { Request, Response, NextFunction } from 'express';
import { JobStore } from '../../services/jobs/job-store';
import { JobStatus } from '../../services/jobs/job.types';
import { formatADAuditResponse } from '../../services/audit/response-formatter';
import { loadConfig } from '../../services/config/config.service';

/**
 * Jobs Controller
 */
export class JobsController {
  private jobStore: JobStore;

  constructor() {
    this.jobStore = JobStore.getInstance();
  }

  /**
   * Get job status
   *
   * GET /api/v1/audit/jobs/:jobId
   */
  async getJobStatus(
    req: Request<{ jobId: string }>,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const { jobId } = req.params;

      const job = this.jobStore.getJob(jobId);

      if (!job) {
        res.status(404).json({
          success: false,
          error: {
            code: 'JOB_NOT_FOUND',
            message: `Job ${jobId} not found`,
          },
        });
        return;
      }

      // If job is completed, format the result like a normal audit response
      if (job.status === 'completed' && job.result) {
        const config = await loadConfig();
        const result = job.result as any;

        // Format response to PRD FR55 structure
        const response = formatADAuditResponse(
          result.score,
          result.findings,
          result.stats,
          {
            domain: {
              name: config.ldap.baseDN,
              baseDN: config.ldap.baseDN,
              ldapUrl: config.ldap.url,
            },
            options: {
              includeDetails: (job.options?.['includeDetails'] as boolean) || false,
              includeComputers: true,
              includeConfig: true,
            },
            executionTimeMs: result.stats.executionTimeMs,
            timestamp: result.timestamp,
            domainConfig: result.domainConfig,
            attackGraph: result.attackGraph,
          }
        );

        res.json({
          job_id: job.job_id,
          type: job.type,
          status: job.status,
          progress: job.progress,
          current_step: job.current_step,
          description: job.description,
          started_at: job.started_at,
          completed_at: job.completed_at,
          duration_ms: job.duration_ms,
          steps: job.steps,
          result: response,
        });
        return;
      }

      // Return job progress for running/pending/failed jobs
      res.json({
        job_id: job.job_id,
        type: job.type,
        status: job.status,
        progress: job.progress,
        current_step: job.current_step,
        description: job.description,
        started_at: job.started_at,
        updated_at: job.updated_at,
        completed_at: job.completed_at,
        failed_at: job.failed_at,
        duration_ms: job.duration_ms,
        steps: job.steps,
        error: job.error,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * List all jobs
   *
   * GET /api/v1/audit/jobs
   * Query params:
   * - status: Filter by job status (pending, running, completed, failed)
   */
  async listJobs(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const statusParam = req.query['status'] as string | undefined;
      let status: JobStatus | undefined;

      if (statusParam && ['pending', 'running', 'completed', 'failed'].includes(statusParam)) {
        status = statusParam as JobStatus;
      }

      const jobs = this.jobStore.listJobs(status);

      res.json({
        success: true,
        data: {
          jobs,
          total: jobs.length,
        },
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Delete/cancel a job
   *
   * DELETE /api/v1/audit/jobs/:jobId
   */
  async deleteJob(
    req: Request<{ jobId: string }>,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const { jobId } = req.params;

      const deleted = this.jobStore.deleteJob(jobId);

      if (!deleted) {
        res.status(404).json({
          success: false,
          error: {
            code: 'JOB_NOT_FOUND',
            message: `Job ${jobId} not found`,
          },
        });
        return;
      }

      res.json({
        success: true,
        message: `Job ${jobId} deleted`,
      });
    } catch (error) {
      next(error);
    }
  }
}
