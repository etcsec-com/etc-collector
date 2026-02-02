/**
 * Daemon Service
 * Manages the polling loop for SaaS mode
 */

import { logInfo, logError, logWarn, logDebug } from '../../utils/logger';
import { SaaSClientService } from './saas-client.service';
import { CommandHandlerService } from './command-handler.service';
import { CollectorConfig, CollectorHealth, FleetCommand } from '../../types/saas.types';

export class DaemonService {
  private readonly saasClient: SaaSClientService;
  private readonly commandHandler: CommandHandlerService;
  private config: CollectorConfig;
  private isRunning: boolean = false;
  private pollingTimeout: NodeJS.Timeout | null = null;
  private readonly startTime: number;
  private lastCommandAt: string | null = null;
  private lastErrorAt: string | null = null;
  private retryDelay: number = 1000; // Start at 1 second
  private readonly maxRetryDelay: number = 5 * 60 * 1000; // 5 minutes max

  constructor(
    saasClient: SaaSClientService,
    commandHandler: CommandHandlerService,
    config: CollectorConfig
  ) {
    this.saasClient = saasClient;
    this.commandHandler = commandHandler;
    this.config = config;
    this.startTime = Date.now();

    // Update command handler config when it changes
    this.commandHandler = new CommandHandlerService(config, (newConfig) => {
      this.updateConfig(newConfig);
    });
  }

  /**
   * Start the daemon polling loop
   */
  async start(): Promise<void> {
    if (this.isRunning) {
      logWarn('Daemon already running');
      return;
    }

    this.isRunning = true;
    logInfo('Starting SaaS daemon', {
      collectorId: this.saasClient.getCollectorId(),
      pollingInterval: this.config.polling.intervalSeconds,
    });

    // Start polling loop
    await this.pollLoop();

    // Send initial health report
    await this.sendHealthReport();

    // Schedule periodic health reports (every 5 minutes)
    setInterval(() => {
      void this.sendHealthReport();
    }, 5 * 60 * 1000);
  }

  /**
   * Stop the daemon
   */
  stop(): void {
    if (!this.isRunning) {
      return;
    }

    this.isRunning = false;

    if (this.pollingTimeout) {
      clearTimeout(this.pollingTimeout);
      this.pollingTimeout = null;
    }

    logInfo('SaaS daemon stopped');
  }

  /**
   * Main polling loop
   */
  private async pollLoop(): Promise<void> {
    if (!this.isRunning) {
      return;
    }

    try {
      // Fetch commands from SaaS
      const response = await this.saasClient.getCommands();

      // Reset retry delay on success
      this.retryDelay = 1000;

      // Process each command
      for (const command of response.commands) {
        await this.processCommand(command);
      }

      // Schedule next poll
      const pollInterval = this.config.polling.intervalSeconds * 1000;
      this.pollingTimeout = setTimeout(() => {
        void this.pollLoop();
      }, pollInterval);

      logDebug('Next poll scheduled', {
        intervalSeconds: this.config.polling.intervalSeconds,
      });
    } catch (error) {
      logError('Polling loop error', error as Error);
      this.lastErrorAt = new Date().toISOString();

      // Exponential backoff: 1s → 2s → 4s → 8s → ... → 5min max
      logWarn('Retrying with exponential backoff', {
        currentDelay: this.retryDelay / 1000,
        nextDelay: Math.min(this.retryDelay * 2, this.maxRetryDelay) / 1000,
      });

      this.pollingTimeout = setTimeout(() => {
        void this.pollLoop();
      }, this.retryDelay);

      // Double the retry delay for next time (up to max)
      this.retryDelay = Math.min(this.retryDelay * 2, this.maxRetryDelay);
    }
  }

  /**
   * Process a single command
   */
  private async processCommand(command: FleetCommand): Promise<void> {
    logInfo('Processing command', {
      commandId: command.commandId,
      type: command.type,
    });

    this.lastCommandAt = new Date().toISOString();

    try {
      // Check if command is expired
      if (command.expiresAt) {
        const expiresAt = new Date(command.expiresAt);
        if (expiresAt < new Date()) {
          logWarn('Command expired, skipping', {
            commandId: command.commandId,
            expiresAt: command.expiresAt,
          });

          // Send timeout result
          await this.saasClient.sendResult({
            commandId: command.commandId,
            status: 'timeout',
            startedAt: new Date().toISOString(),
            completedAt: new Date().toISOString(),
            error: {
              code: 'COMMAND_EXPIRED',
              message: 'Command expired before execution',
            },
          });

          return;
        }
      }

      // Acknowledge command receipt
      await this.saasClient.acknowledgeCommand(command.commandId);

      // Execute command
      const result = await this.commandHandler.executeCommand(command);

      // Send result to SaaS
      await this.saasClient.sendResult(result);

      logInfo('Command completed successfully', {
        commandId: command.commandId,
        status: result.status,
      });
    } catch (error) {
      logError('Command processing failed', error as Error);

      // Try to send error result
      try {
        await this.saasClient.sendResult({
          commandId: command.commandId,
          status: 'error',
          startedAt: new Date().toISOString(),
          completedAt: new Date().toISOString(),
          error: {
            code: 'COMMAND_PROCESSING_ERROR',
            message: (error as Error).message,
            details: (error as Error).stack,
          },
        });
      } catch (sendError) {
        logError('Failed to send error result', sendError as Error);
      }
    }
  }

  /**
   * Send health report to SaaS
   */
  private async sendHealthReport(): Promise<void> {
    try {
      const memoryUsage = process.memoryUsage();

      const health: CollectorHealth = {
        status: 'healthy',
        uptime: Math.floor((Date.now() - this.startTime) / 1000),
        lastCommandAt: this.lastCommandAt || undefined,
        lastErrorAt: this.lastErrorAt || undefined,
        ldapConnected: !!this.config.ldap,
        azureConnected: this.config.azure?.enabled || false,
        memoryUsageMB: Math.round(memoryUsage.heapUsed / 1024 / 1024),
        version: process.env['npm_package_version'] || 'unknown',
      };

      await this.saasClient.sendHealth(health);
      logDebug('Health report sent');
    } catch (error) {
      logError('Failed to send health report', error as Error);
    }
  }

  /**
   * Update configuration
   */
  private updateConfig(config: CollectorConfig): void {
    logInfo('Updating daemon configuration');
    this.config = config;
    this.commandHandler.updateConfig(config);
  }

  /**
   * Check if daemon is running
   */
  isActive(): boolean {
    return this.isRunning;
  }
}
