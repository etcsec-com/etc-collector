/**
 * PowerShell Logging Disabled Detector
 * Check if PowerShell logging is disabled
 * Requires GPO settings from SYSVOL
 */

import { ADDomain } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { GpoSecuritySettings } from '../types';

export function detectPowershellLoggingDisabled(
  gpoSettings: GpoSecuritySettings | null,
  domain: ADDomain | null,
  includeDetails: boolean
): Finding {
  if (gpoSettings && gpoSettings.powershellLogging) {
    const logging = gpoSettings.powershellLogging;
    const loggingDisabled = !logging.moduleLogging && !logging.scriptBlockLogging;

    return {
      type: 'POWERSHELL_LOGGING_DISABLED',
      severity: 'medium',
      category: 'advanced',
      title: 'PowerShell Logging Not Configured',
      description:
        'PowerShell script block logging and module logging are not enabled. Malicious PowerShell activity will not be logged.',
      count: loggingDisabled ? 1 : 0,
      affectedEntities: includeDetails && loggingDisabled && domain ? [domain.dn] : undefined,
      details: loggingDisabled
        ? {
            recommendation:
              'Enable "Turn on PowerShell Script Block Logging" and "Turn on Module Logging" via GPO.',
            moduleLogging: logging.moduleLogging,
            scriptBlockLogging: logging.scriptBlockLogging,
            transcription: logging.transcription,
          }
        : undefined,
    };
  }

  return {
    type: 'POWERSHELL_LOGGING_DISABLED',
    severity: 'medium',
    category: 'advanced',
    title: 'PowerShell Logging Configuration Unknown',
    description: 'Unable to determine PowerShell logging configuration. Manual review recommended.',
    count: 0,
    details: {
      note: 'GPO/Registry settings not available. Check PowerShell logging GPO settings manually.',
    },
  };
}
