/**
 * SaaS Integration Types
 * Types for collector enrollment and fleet management
 */

/**
 * CLI arguments for SaaS mode
 */
export interface CLIArgs {
  mode: 'standalone' | 'saas';
  enroll?: boolean;
  daemon?: boolean;
  token?: string;
  saasUrl?: string;
  status?: boolean;
  unenroll?: boolean;
  help?: boolean;
  version?: boolean;
}

/**
 * Enrollment request sent to SaaS
 */
export interface EnrollmentRequest {
  enrollmentToken: string;
  hostname: string;
  osType: string;
  osVersion: string;
  collectorVersion: string;
  capabilities: string[];
}

/**
 * Enrollment response from SaaS
 */
export interface EnrollmentResponse {
  success: boolean;
  collectorId: string;
  apiKey: string;
  config: CollectorConfig;
  message?: string;
}

/**
 * Configuration received from SaaS after enrollment
 */
export interface CollectorConfig {
  ldap?: {
    url: string;
    bindDN: string;
    bindPassword: string;
    baseDN: string;
    tlsVerify: boolean;
    caCert?: string;
    timeout?: number;
    skipHostnameVerification?: boolean;
    tlsServername?: string;
  };
  azure?: {
    enabled: boolean;
    tenantId?: string;
    tenantName?: string;
    clientId?: string;
    clientSecret?: string;
  };
  polling: {
    intervalSeconds: number;
    commandTimeoutSeconds: number;
  };
}

/**
 * Command types from SaaS
 */
export type CommandType =
  | 'RUN_AUDIT'
  | 'RUN_AUDIT_AZURE'
  | 'UPDATE_CONFIG'
  | 'RESTART'
  | 'HEALTH_CHECK'
  | 'UNENROLL';

/**
 * Command from SaaS fleet management
 */
export interface FleetCommand {
  commandId: string;
  type: CommandType;
  parameters?: Record<string, unknown>;
  createdAt: string;
  expiresAt?: string;
}

/**
 * Commands response from SaaS
 */
export interface FleetCommandsResponse {
  commands: FleetCommand[];
  nextPollAt?: string;
}

/**
 * Result status for command execution
 */
export type CommandResultStatus = 'success' | 'error' | 'timeout' | 'cancelled';

/**
 * Result sent back to SaaS after command execution
 */
export interface FleetCommandResult {
  commandId: string;
  status: CommandResultStatus;
  startedAt: string;
  completedAt: string;
  result?: unknown;
  error?: {
    code: string;
    message: string;
    details?: string;
  };
}

/**
 * Local storage for enrolled collector credentials
 */
export interface CollectorCredentials {
  collectorId: string;
  apiKey: string;
  saasUrl: string;
  enrolledAt: string;
  config: CollectorConfig;
}

/**
 * Health status reported to SaaS
 */
export interface CollectorHealth {
  status: 'healthy' | 'degraded' | 'unhealthy';
  uptime: number;
  lastCommandAt?: string;
  lastErrorAt?: string;
  ldapConnected: boolean;
  azureConnected: boolean;
  memoryUsageMB: number;
  version: string;
}
