/**
 * SaaS Client Service
 * Handles all communication with the ETC SaaS platform
 */

import { logInfo, logError, logDebug } from '../../utils/logger';
import {
  EnrollmentRequest,
  EnrollmentResponse,
  FleetCommandsResponse,
  FleetCommandResult,
  CollectorHealth,
} from '../../types/saas.types';

export class SaaSClientService {
  private readonly saasUrl: string;
  private apiKey: string | null = null;
  private collectorId: string | null = null;

  constructor(saasUrl: string) {
    // Normalize URL (remove trailing slash)
    this.saasUrl = saasUrl.replace(/\/$/, '');
  }

  /**
   * Set credentials after enrollment
   */
  setCredentials(collectorId: string, apiKey: string): void {
    this.collectorId = collectorId;
    this.apiKey = apiKey;
  }

  /**
   * Get the collector ID
   */
  getCollectorId(): string | null {
    return this.collectorId;
  }

  /**
   * Enroll this collector with the SaaS platform
   */
  async enroll(request: EnrollmentRequest): Promise<EnrollmentResponse> {
    logInfo('Enrolling collector with SaaS', {
      saasUrl: this.saasUrl,
      hostname: request.hostname,
    });

    try {
      const response = await fetch(`${this.saasUrl}/api/fleet/enroll`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Enrollment-Token': request.enrollmentToken,
        },
        body: JSON.stringify(request),
      });

      if (!response.ok) {
        const errorBody = await response.text();
        throw new Error(
          `Enrollment failed: ${response.status} ${response.statusText} - ${errorBody}`
        );
      }

      const result = (await response.json()) as EnrollmentResponse;

      if (result.success) {
        this.setCredentials(result.collectorId, result.apiKey);
        logInfo('Enrollment successful', {
          collectorId: result.collectorId,
        });
      }

      return result;
    } catch (error) {
      logError('Enrollment failed', error as Error);
      throw error;
    }
  }

  /**
   * Fetch pending commands from SaaS
   */
  async getCommands(): Promise<FleetCommandsResponse> {
    this.ensureAuthenticated();

    logDebug('Fetching commands from SaaS');

    try {
      const response = await fetch(
        `${this.saasUrl}/api/fleet/collectors/${this.collectorId}/commands`,
        {
          method: 'GET',
          headers: this.getAuthHeaders(),
        }
      );

      if (!response.ok) {
        const errorBody = await response.text();
        throw new Error(
          `Failed to get commands: ${response.status} ${response.statusText} - ${errorBody}`
        );
      }

      const result = (await response.json()) as FleetCommandsResponse;
      logDebug('Received commands', { count: result.commands.length });

      return result;
    } catch (error) {
      logError('Failed to fetch commands', error as Error);
      throw error;
    }
  }

  /**
   * Send command execution result to SaaS
   */
  async sendResult(result: FleetCommandResult): Promise<void> {
    this.ensureAuthenticated();

    logInfo('Sending command result to SaaS', {
      commandId: result.commandId,
      status: result.status,
    });

    try {
      const response = await fetch(
        `${this.saasUrl}/api/fleet/collectors/${this.collectorId}/results`,
        {
          method: 'POST',
          headers: this.getAuthHeaders(),
          body: JSON.stringify(result),
        }
      );

      if (!response.ok) {
        const errorBody = await response.text();
        throw new Error(
          `Failed to send result: ${response.status} ${response.statusText} - ${errorBody}`
        );
      }

      logDebug('Result sent successfully', { commandId: result.commandId });
    } catch (error) {
      logError('Failed to send result', error as Error);
      throw error;
    }
  }

  /**
   * Send health status to SaaS
   */
  async sendHealth(health: CollectorHealth): Promise<void> {
    this.ensureAuthenticated();

    try {
      const response = await fetch(
        `${this.saasUrl}/api/fleet/collectors/${this.collectorId}/health`,
        {
          method: 'POST',
          headers: this.getAuthHeaders(),
          body: JSON.stringify(health),
        }
      );

      if (!response.ok) {
        logError('Failed to send health', new Error(`HTTP ${response.status}`));
      }
    } catch (error) {
      // Don't throw on health check failures
      logError('Health check failed', error as Error);
    }
  }

  /**
   * Acknowledge a command (mark as received)
   */
  async acknowledgeCommand(commandId: string): Promise<void> {
    this.ensureAuthenticated();

    try {
      await fetch(
        `${this.saasUrl}/api/fleet/collectors/${this.collectorId}/commands/${commandId}/ack`,
        {
          method: 'POST',
          headers: this.getAuthHeaders(),
        }
      );
    } catch (error) {
      logError('Failed to acknowledge command', error as Error);
    }
  }

  /**
   * Get SaaS URL
   */
  getSaaSUrl(): string {
    return this.saasUrl;
  }

  /**
   * Check if we're authenticated
   */
  private ensureAuthenticated(): void {
    if (!this.apiKey || !this.collectorId) {
      throw new Error('Collector not enrolled. Run with --enroll first.');
    }
  }

  /**
   * Get authentication headers
   */
  private getAuthHeaders(): Record<string, string> {
    return {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${this.apiKey}`,
      'X-Collector-ID': this.collectorId!,
    };
  }
}
