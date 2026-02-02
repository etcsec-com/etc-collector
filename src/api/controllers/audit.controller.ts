/**
 * Audit Controller
 *
 * Handles AD and Azure audit operations.
 * Story 1.10: API Controllers & Routes
 *
 * Endpoints:
 * - POST /api/v1/audit/ad - Run AD audit (sync or async with ?async=true)
 * - GET /api/v1/audit/ad/status - Test LDAP connection
 * - POST /api/v1/audit/azure - Run Azure audit
 * - GET /api/v1/audit/azure/status - Test Graph connection
 */

import { Request, Response, NextFunction } from 'express';
import { ADAuditService } from '../../services/audit/ad-audit.service';
import { AzureAuditService } from '../../services/audit/azure-audit.service';
import { LDAPProvider } from '../../providers/ldap/ldap.provider';
import { GraphProvider } from '../../providers/azure/graph.provider';
import { loadConfig } from '../../services/config/config.service';
import { formatADAuditResponse } from '../../services/audit/response-formatter';
import { JobRunner } from '../../services/jobs/job-runner';
import { AzureJobRunner } from '../../services/jobs/azure-job-runner';

/**
 * AD Audit request body
 */
interface ADAuditRequest {
  includeDetails?: boolean;
  maxUsers?: number;
  maxGroups?: number;
  maxComputers?: number;
}

/**
 * Azure Audit request body
 */
interface AzureAuditRequest {
  includeDetails?: boolean;
  maxUsers?: number;
  maxGroups?: number;
  maxApps?: number;
}

/**
 * Audit Controller
 */
export class AuditController {
  /**
   * Run AD audit
   *
   * POST /api/v1/audit/ad
   * Query params:
   * - async=true: Run audit asynchronously, returns job_id for polling
   */
  async runADAudit(
    req: Request<object, object, ADAuditRequest>,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const { includeDetails = false, maxUsers, maxGroups, maxComputers } = req.body;
      const asyncMode = req.query['async'] === 'true';

      // Load configuration
      const config = await loadConfig();

      // Create LDAP provider
      const ldapProvider = new LDAPProvider(config.ldap);

      // ASYNC MODE: Start job and return immediately
      if (asyncMode) {
        // Connect first to verify credentials work
        await ldapProvider.connect();

        // Create job runner with SMB config
        const smbConfig = { smb: config.smb, ldap: config.ldap };
        const jobRunner = new JobRunner(ldapProvider, smbConfig);
        const job = jobRunner.startAudit({
          includeDetails,
          maxUsers,
          maxGroups,
          maxComputers,
        });

        // Return job info immediately (don't wait for audit)
        res.status(202).json({
          job_id: job.job_id,
          status: job.status,
          progress: job.progress,
          current_step: job.current_step,
          description: job.description,
          started_at: job.started_at,
          steps: job.steps,
        });
        return;
      }

      // SYNC MODE: Wait for audit completion (original behavior)
      await ldapProvider.connect();

      try {
        // Create AD audit service with SMB config
        const smbConfig = { smb: config.smb, ldap: config.ldap };
        const adAuditService = new ADAuditService(ldapProvider, smbConfig);

        // Run audit
        const result = await adAuditService.runAudit({
          includeDetails,
          maxUsers,
          maxGroups,
          maxComputers,
        });

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
              includeDetails,
              includeComputers: maxComputers !== 0,
              includeConfig: true,
            },
            executionTimeMs: result.stats.executionTimeMs,
            timestamp: result.timestamp,
            domainConfig: result.domainConfig,
            attackGraph: result.attackGraph,
          }
        );

        res.json(response);
      } finally {
        // Ensure disconnection
        await ldapProvider.disconnect();
      }
    } catch (error) {
      next(error);
    }
  }

  /**
   * Test LDAP connection
   *
   * GET /api/v1/audit/ad/status
   */
  async getADStatus(
    _req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      // Load configuration
      const config = await loadConfig();

      // Create LDAP provider
      const ldapProvider = new LDAPProvider(config.ldap);

      // Test connection
      const result = await ldapProvider.testConnection();

      // Disconnect
      await ldapProvider.disconnect();

      res.json({
        success: result.success,
        message: result.message,
        details: result.details,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Run Azure audit
   *
   * POST /api/v1/audit/azure
   * Query params:
   * - async=true: Run audit asynchronously, returns job_id for polling
   */
  async runAzureAudit(
    req: Request<object, object, AzureAuditRequest>,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const { includeDetails = false, maxUsers, maxGroups, maxApps } = req.body;
      const asyncMode = req.query['async'] === 'true';

      // Load configuration
      const config = await loadConfig();

      // Check if Azure is enabled
      if (!config.azure.enabled || !config.azure.tenantId || !config.azure.clientId || !config.azure.clientSecret) {
        res.status(400).json({
          success: false,
          error: {
            code: 'AZURE_NOT_CONFIGURED',
            message: 'Azure AD is not configured. Set AZURE_ENABLED=true and provide credentials.',
          },
        });
        return;
      }

      // Create Graph provider
      const graphProvider = new GraphProvider({
        tenantId: config.azure.tenantId,
        clientId: config.azure.clientId,
        clientSecret: config.azure.clientSecret,
      });

      // ASYNC MODE: Start job and return immediately
      if (asyncMode) {
        // Test authentication first
        await graphProvider.authenticate();

        // Create Azure job runner
        const azureJobRunner = new AzureJobRunner(graphProvider);
        const job = azureJobRunner.startAudit({
          includeDetails,
          maxUsers,
          maxGroups,
          maxApps,
        });

        // Return job info immediately (don't wait for audit)
        res.status(202).json({
          job_id: job.job_id,
          status: job.status,
          progress: job.progress,
          current_step: job.current_step,
          description: job.description,
          started_at: job.started_at,
          steps: job.steps,
        });
        return;
      }

      // SYNC MODE: Wait for audit completion (original behavior)
      // Create Azure audit service
      const azureAuditService = new AzureAuditService(graphProvider);

      // Run audit
      const result = await azureAuditService.runAudit({
        includeDetails,
        maxUsers,
        maxGroups,
        maxApps,
      });

      res.json({
        success: true,
        data: result,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Test Microsoft Graph connection
   *
   * GET /api/v1/audit/azure/status
   */
  async getAzureStatus(
    _req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      // Load configuration
      const config = await loadConfig();

      // Check if Azure is enabled
      if (!config.azure.enabled || !config.azure.tenantId || !config.azure.clientId || !config.azure.clientSecret) {
        res.status(400).json({
          success: false,
          error: {
            code: 'AZURE_NOT_CONFIGURED',
            message: 'Azure AD is not configured. Set AZURE_ENABLED=true and provide credentials.',
          },
        });
        return;
      }

      // Create Graph provider
      const graphProvider = new GraphProvider({
        tenantId: config.azure.tenantId,
        clientId: config.azure.clientId,
        clientSecret: config.azure.clientSecret,
      });

      // Create Azure audit service
      const azureAuditService = new AzureAuditService(graphProvider);

      // Test connection
      const result = await azureAuditService.testConnection();

      res.json({
        success: result.success,
        message: result.message,
      });
    } catch (error) {
      next(error);
    }
  }
}
