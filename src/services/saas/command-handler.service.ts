/**
 * Command Handler Service
 * Routes and executes commands received from SaaS
 */

import { logInfo, logError, logWarn } from '../../utils/logger';
import {
  FleetCommand,
  FleetCommandResult,
  CollectorConfig,
} from '../../types/saas.types';
import { DIContainer } from '../../container';
import { ADAuditService } from '../audit/ad-audit.service';
import { AzureAuditService } from '../audit/azure-audit.service';

export class CommandHandlerService {
  private config: CollectorConfig;
  private readonly onConfigUpdate?: (config: CollectorConfig) => void;

  constructor(config: CollectorConfig, onConfigUpdate?: (config: CollectorConfig) => void) {
    this.config = config;
    this.onConfigUpdate = onConfigUpdate;
  }

  /**
   * Execute a command received from SaaS
   */
  async executeCommand(command: FleetCommand): Promise<FleetCommandResult> {
    const startedAt = new Date().toISOString();
    logInfo('Executing command', {
      commandId: command.commandId,
      type: command.type,
    });

    try {
      let result: unknown;

      switch (command.type) {
        case 'RUN_AUDIT':
          result = await this.handleRunAudit(command);
          break;

        case 'RUN_AUDIT_AZURE':
          result = await this.handleRunAuditAzure(command);
          break;

        case 'UPDATE_CONFIG':
          result = await this.handleUpdateConfig(command);
          break;

        case 'HEALTH_CHECK':
          result = await this.handleHealthCheck(command);
          break;

        case 'RESTART':
          result = await this.handleRestart(command);
          break;

        default:
          throw new Error(`Unknown command type: ${command.type}`);
      }

      const completedAt = new Date().toISOString();

      return {
        commandId: command.commandId,
        status: 'success',
        startedAt,
        completedAt,
        result,
      };
    } catch (error) {
      logError('Command execution failed', error as Error);

      const completedAt = new Date().toISOString();

      return {
        commandId: command.commandId,
        status: 'error',
        startedAt,
        completedAt,
        error: {
          code: (error as Error).name || 'COMMAND_EXECUTION_ERROR',
          message: (error as Error).message,
          details: (error as Error).stack,
        },
      };
    }
  }

  /**
   * Handle RUN_AUDIT command
   */
  private async handleRunAudit(command: FleetCommand): Promise<unknown> {
    logInfo('Running AD audit', { parameters: command.parameters });

    // Get LDAP provider from container
    const ldapProvider = DIContainer.getInstance().getLDAPProvider();

    const options = {
      includeDetails: command.parameters?.['includeDetails'] as boolean | undefined,
      maxUsers: command.parameters?.['maxUsers'] as number | undefined,
      maxGroups: command.parameters?.['maxGroups'] as number | undefined,
      maxComputers: command.parameters?.['maxComputers'] as number | undefined,
    };

    // Connect to LDAP
    await ldapProvider.connect();

    try {
      // Create AD audit service (no SMB config in SaaS mode)
      const smbConfig = {
        smb: { enabled: false, timeout: 10000 },
        ldap: {
          ...this.config.ldap!,
          timeout: this.config.ldap!.timeout || 30000,
        },
      };
      const adAuditService = new ADAuditService(ldapProvider, smbConfig);

      // Run audit
      const result = await adAuditService.runAudit(options);

      logInfo('AD audit completed', {
        findingsCount: result.findings.length,
        score: result.score,
      });

      // Return simplified result (full result can be large)
      return {
        score: result.score,
        findings: result.findings,
        stats: result.stats,
        summary: {
          critical: result.findings.filter((f) => f.severity === 'critical').length,
          high: result.findings.filter((f) => f.severity === 'high').length,
          medium: result.findings.filter((f) => f.severity === 'medium').length,
          low: result.findings.filter((f) => f.severity === 'low').length,
        },
      };
    } finally {
      // Ensure disconnection
      await ldapProvider.disconnect();
    }
  }

  /**
   * Handle RUN_AUDIT_AZURE command
   */
  private async handleRunAuditAzure(command: FleetCommand): Promise<unknown> {
    logInfo('Running Azure audit', { parameters: command.parameters });

    if (!this.config.azure?.enabled) {
      throw new Error('Azure audit not configured');
    }

    // Get Graph provider from container
    const graphProvider = DIContainer.getInstance().getGraphProvider();

    const options = {
      includeDetails: command.parameters?.['includeDetails'] as boolean | undefined,
    };

    // Create Azure audit service
    const azureAuditService = new AzureAuditService(graphProvider);

    // Run audit
    const result = await azureAuditService.runAudit(options);

    logInfo('Azure audit completed', {
      findingsCount: result.findings.length,
      score: result.score,
    });

    // Return simplified result
    return {
      score: result.score,
      findings: result.findings,
      stats: result.stats,
      summary: {
        critical: result.findings.filter((f) => f.severity === 'critical').length,
        high: result.findings.filter((f) => f.severity === 'high').length,
        medium: result.findings.filter((f) => f.severity === 'medium').length,
        low: result.findings.filter((f) => f.severity === 'low').length,
      },
    };
  }

  /**
   * Handle UPDATE_CONFIG command
   */
  private async handleUpdateConfig(command: FleetCommand): Promise<unknown> {
    logInfo('Updating configuration');

    const newConfig = command.parameters?.['config'] as CollectorConfig;

    if (!newConfig) {
      throw new Error('Missing config parameter');
    }

    // Update local config
    this.config = newConfig;

    // Notify callback if provided
    if (this.onConfigUpdate) {
      this.onConfigUpdate(newConfig);
    }

    logInfo('Configuration updated');

    return {
      success: true,
      message: 'Configuration updated successfully',
    };
  }

  /**
   * Handle HEALTH_CHECK command
   */
  private async handleHealthCheck(_command: FleetCommand): Promise<unknown> {
    logInfo('Running health check');

    // Test LDAP connection if configured
    let ldapConnected = false;
    if (this.config.ldap) {
      try {
        const ldapProvider = DIContainer.getInstance().getLDAPProvider();
        await ldapProvider.testConnection();
        ldapConnected = true;
      } catch (error) {
        logWarn('LDAP connection failed during health check');
      }
    }

    // Test Azure connection if configured
    let azureConnected = false;
    if (this.config.azure?.enabled) {
      try {
        // Azure health check not implemented yet
        azureConnected = false;
      } catch (error) {
        logWarn('Azure connection failed during health check');
      }
    }

    const memoryUsage = process.memoryUsage();

    return {
      status: ldapConnected || azureConnected ? 'healthy' : 'unhealthy',
      uptime: process.uptime(),
      ldapConnected,
      azureConnected,
      memoryUsageMB: Math.round(memoryUsage.heapUsed / 1024 / 1024),
      version: process.env['npm_package_version'] || 'unknown',
    };
  }

  /**
   * Handle RESTART command
   */
  private async handleRestart(_command: FleetCommand): Promise<unknown> {
    logWarn('Restart command received - will restart after sending response');

    // Schedule restart after response is sent
    setTimeout(() => {
      logInfo('Restarting collector...');
      process.exit(0); // Assuming a process manager will restart
    }, 1000);

    return {
      success: true,
      message: 'Restart scheduled in 1 second',
    };
  }

  /**
   * Update configuration
   */
  updateConfig(config: CollectorConfig): void {
    this.config = config;
  }
}
