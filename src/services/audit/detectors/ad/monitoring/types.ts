/**
 * Monitoring Detector Types
 *
 * Shared type definitions for monitoring and security supervision detection.
 */

import { GpoSecuritySettings } from '../../../../../providers/smb/smb.provider';

/**
 * Extended GPO settings for monitoring analysis
 */
export interface MonitoringGpoSettings extends GpoSecuritySettings {
  /** Event log maximum size settings (in KB) */
  eventLogSettings?: {
    securityLogMaxSize?: number;
    systemLogMaxSize?: number;
    applicationLogMaxSize?: number;
  };
}

/**
 * Monitoring detector options
 */
export interface MonitoringDetectorOptions {
  /** GPO security settings including event log settings */
  gpoSettings?: MonitoringGpoSettings | null;
}
