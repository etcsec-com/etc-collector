/**
 * Job Store
 *
 * In-memory store for managing async audit jobs.
 * Provides thread-safe operations for job lifecycle management.
 */

import { v4 as uuidv4 } from 'uuid';
import {
  Job,
  JobStatus,
  JobStep,
  JobError,
  CreateJobOptions,
  StepProgressUpdate,
  JobSummary,
  AuditStepName,
  AD_AUDIT_STEPS,
  AZURE_AUDIT_STEPS,
  StepDefinition,
} from './job.types';
import { logger } from '../../utils/logger';

/**
 * Maximum number of completed jobs to keep in memory
 */
const MAX_COMPLETED_JOBS = 100;

/**
 * Time to keep completed jobs (1 hour)
 */
const JOB_RETENTION_MS = 60 * 60 * 1000;

/**
 * Job Store
 *
 * Singleton store for managing audit jobs in memory.
 */
export class JobStore {
  private static instance: JobStore;
  private jobs: Map<string, Job> = new Map();
  private cleanupInterval: NodeJS.Timeout | null = null;

  private constructor() {
    // Start cleanup interval
    this.cleanupInterval = setInterval(() => this.cleanup(), 5 * 60 * 1000); // Every 5 minutes
  }

  /**
   * Get singleton instance
   */
  static getInstance(): JobStore {
    if (!JobStore.instance) {
      JobStore.instance = new JobStore();
    }
    return JobStore.instance;
  }

  /**
   * Create a new job
   */
  createJob(options: CreateJobOptions): Job {
    const now = new Date().toISOString();
    const jobId = `${options.type}-${Date.now()}-${uuidv4().substring(0, 8)}`;

    // Get step definitions based on job type
    const stepDefs = this.getStepDefinitions(options.type);

    // Initialize steps
    const steps: JobStep[] = stepDefs.map((def) => ({
      name: def.name,
      status: 'pending',
      description: def.description,
    }));

    const job: Job = {
      job_id: jobId,
      type: options.type,
      status: 'pending',
      progress: 0,
      current_step: steps[0]?.name || 'CONNECTING',
      description: 'Job created, waiting to start',
      started_at: now,
      updated_at: now,
      steps,
      options: options.options,
    };

    this.jobs.set(jobId, job);
    logger.info('Job created', { job_id: jobId, type: options.type });

    return job;
  }

  /**
   * Get step definitions for job type
   */
  private getStepDefinitions(type: string): StepDefinition[] {
    switch (type) {
      case 'ad-audit':
        return AD_AUDIT_STEPS;
      case 'azure-audit':
        return AZURE_AUDIT_STEPS;
      default:
        return AD_AUDIT_STEPS;
    }
  }

  /**
   * Get a job by ID
   */
  getJob(jobId: string): Job | undefined {
    return this.jobs.get(jobId);
  }

  /**
   * List all jobs (optionally filtered by status)
   */
  listJobs(status?: JobStatus): JobSummary[] {
    const summaries: JobSummary[] = [];

    for (const job of this.jobs.values()) {
      if (!status || job.status === status) {
        summaries.push({
          job_id: job.job_id,
          type: job.type,
          status: job.status,
          progress: job.progress,
          current_step: job.current_step,
          started_at: job.started_at,
          completed_at: job.completed_at,
          duration_ms: job.duration_ms,
        });
      }
    }

    // Sort by started_at descending
    return summaries.sort(
      (a, b) => new Date(b.started_at).getTime() - new Date(a.started_at).getTime()
    );
  }

  /**
   * Start a job
   */
  startJob(jobId: string): void {
    const job = this.jobs.get(jobId);
    if (!job) return;

    job.status = 'running';
    job.description = 'Audit in progress';
    job.updated_at = new Date().toISOString();

    logger.info('Job started', { job_id: jobId });
  }

  /**
   * Start a step
   */
  startStep(jobId: string, stepName: AuditStepName, description?: string): void {
    const job = this.jobs.get(jobId);
    if (!job) return;

    const step = job.steps.find((s) => s.name === stepName);
    if (!step) return;

    step.status = 'running';
    step.started_at = new Date().toISOString();
    if (description) {
      step.description = description;
    }

    job.current_step = stepName;
    job.description = step.description;
    job.updated_at = new Date().toISOString();
    job.progress = this.calculateProgress(job);

    logger.debug('Step started', { job_id: jobId, step: stepName });
  }

  /**
   * Update step progress
   */
  updateStepProgress(jobId: string, stepName: AuditStepName, update: StepProgressUpdate): void {
    const job = this.jobs.get(jobId);
    if (!job) return;

    const step = job.steps.find((s) => s.name === stepName);
    if (!step) return;

    if (update.progress !== undefined) step.progress = update.progress;
    if (update.count !== undefined) step.count = update.count;
    if (update.findings !== undefined) step.findings = update.findings;
    if (update.description) {
      step.description = update.description;
      job.description = update.description;
    }

    job.updated_at = new Date().toISOString();
    job.progress = this.calculateProgress(job);
  }

  /**
   * Complete a step
   */
  completeStep(
    jobId: string,
    stepName: AuditStepName,
    result?: { count?: number; findings?: number }
  ): void {
    const job = this.jobs.get(jobId);
    if (!job) return;

    const step = job.steps.find((s) => s.name === stepName);
    if (!step) return;

    const now = new Date().toISOString();
    step.status = 'completed';
    step.completed_at = now;
    step.progress = 100;

    if (step.started_at) {
      step.duration_ms = new Date(now).getTime() - new Date(step.started_at).getTime();
    }

    if (result?.count !== undefined) step.count = result.count;
    if (result?.findings !== undefined) step.findings = result.findings;

    job.updated_at = now;
    job.progress = this.calculateProgress(job);

    logger.debug('Step completed', {
      job_id: jobId,
      step: stepName,
      duration_ms: step.duration_ms,
      count: step.count,
      findings: step.findings,
    });
  }

  /**
   * Fail a step
   */
  failStep(jobId: string, stepName: AuditStepName, error: string): void {
    const job = this.jobs.get(jobId);
    if (!job) return;

    const step = job.steps.find((s) => s.name === stepName);
    if (!step) return;

    const now = new Date().toISOString();
    step.status = 'failed';
    step.completed_at = now;
    step.error = error;

    if (step.started_at) {
      step.duration_ms = new Date(now).getTime() - new Date(step.started_at).getTime();
    }

    job.updated_at = now;
  }

  /**
   * Complete the job
   */
  completeJob<T>(jobId: string, result: T): void {
    const job = this.jobs.get(jobId);
    if (!job) return;

    const now = new Date().toISOString();
    job.status = 'completed';
    job.progress = 100;
    job.current_step = 'COMPLETED';
    job.description = 'Audit completed successfully';
    job.completed_at = now;
    job.updated_at = now;
    job.duration_ms = new Date(now).getTime() - new Date(job.started_at).getTime();
    job.result = result;

    logger.info('Job completed', {
      job_id: jobId,
      duration_ms: job.duration_ms,
      steps_completed: job.steps.filter((s) => s.status === 'completed').length,
    });
  }

  /**
   * Fail the job
   */
  failJob(jobId: string, error: JobError): void {
    const job = this.jobs.get(jobId);
    if (!job) return;

    const now = new Date().toISOString();
    job.status = 'failed';
    job.description = error.message;
    job.failed_at = now;
    job.updated_at = now;
    job.duration_ms = new Date(now).getTime() - new Date(job.started_at).getTime();
    job.error = error;

    logger.error('Job failed', {
      job_id: jobId,
      error: error.code,
      message: error.message,
      step: error.step,
    });
  }

  /**
   * Calculate overall progress based on step weights
   */
  private calculateProgress(job: Job): number {
    const stepDefs = this.getStepDefinitions(job.type);
    let completedWeight = 0;
    let currentStepPartialWeight = 0;

    for (const step of job.steps) {
      const def = stepDefs.find((d) => d.name === step.name);
      if (!def) continue;

      if (step.status === 'completed') {
        completedWeight += def.weight;
      } else if (step.status === 'running' && step.progress !== undefined) {
        currentStepPartialWeight = (def.weight * step.progress) / 100;
      }
    }

    return Math.min(100, Math.round(completedWeight + currentStepPartialWeight));
  }

  /**
   * Delete a job
   */
  deleteJob(jobId: string): boolean {
    const deleted = this.jobs.delete(jobId);
    if (deleted) {
      logger.info('Job deleted', { job_id: jobId });
    }
    return deleted;
  }

  /**
   * Cleanup old completed/failed jobs
   */
  private cleanup(): void {
    const now = Date.now();
    const jobsToDelete: string[] = [];

    for (const [jobId, job] of this.jobs.entries()) {
      if (job.status === 'completed' || job.status === 'failed') {
        const completedTime = job.completed_at || job.failed_at;
        if (completedTime && now - new Date(completedTime).getTime() > JOB_RETENTION_MS) {
          jobsToDelete.push(jobId);
        }
      }
    }

    // Also cleanup if we have too many completed jobs
    const completedJobs = this.listJobs('completed');
    if (completedJobs.length > MAX_COMPLETED_JOBS) {
      const excess = completedJobs.slice(MAX_COMPLETED_JOBS);
      excess.forEach((j) => jobsToDelete.push(j.job_id));
    }

    for (const jobId of jobsToDelete) {
      this.jobs.delete(jobId);
    }

    if (jobsToDelete.length > 0) {
      logger.info('Cleaned up old jobs', { count: jobsToDelete.length });
    }
  }

  /**
   * Stop the store (cleanup interval)
   */
  stop(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }
}
