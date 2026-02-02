/**
 * CHANGE_MANAGEMENT_BYPASS - Changes outside approved process
 * Frameworks: SOX Section 404, ISO27001 A.12.1.2, SOC2 CC8.1
 * Detects admin changes that may bypass change management
 */

import { ADUser, ADGroup } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';

export function detectChangeManagementBypass(
  users: ADUser[],
  groups: ADGroup[],
  _includeDetails: boolean
): Finding {
  const issues: string[] = [];
  const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;
  const now = Date.now();

  const privilegedGroupNames = ['Domain Admins', 'Enterprise Admins', 'Schema Admins'];

  // Check for recent privileged group changes (potential bypass indicators)
  for (const group of groups) {
    if (!privilegedGroupNames.some(pg => group.sAMAccountName?.toLowerCase() === pg.toLowerCase())) {
      continue;
    }

    const groupChanged = group['whenChanged'] as Date | undefined;
    if (groupChanged && (now - groupChanged.getTime()) < SEVEN_DAYS_MS) {
      issues.push(`${group.sAMAccountName} modified in last 7 days - verify change request exists`);
    }
  }

  // Check for recently created admin accounts
  const recentAdmins = users.filter((u) => {
    if (!u.memberOf?.some((dn) => privilegedGroupNames.some((pg) => dn.includes(`CN=${pg}`)))) {
      return false;
    }
    const created = u['whenCreated'] as Date | undefined;
    return created && (now - created.getTime()) < SEVEN_DAYS_MS;
  });

  if (recentAdmins.length > 0) {
    issues.push(`${recentAdmins.length} privileged accounts created in last 7 days - verify change requests`);
  }

  return {
    type: 'CHANGE_MANAGEMENT_BYPASS',
    severity: 'high',
    category: 'compliance',
    title: 'Potential Change Management Bypass',
    description:
      'Recent privileged changes detected - verify change management process was followed. Required by SOX Section 404, ISO27001 A.12.1.2, SOC2 CC8.1.',
    count: issues.length > 0 ? 1 : 0,
    details: issues.length > 0 ? {
      violations: issues,
      frameworks: ['SOX', 'ISO27001', 'SOC2'],
      controls: ['Section 404', 'A.12.1.2', 'CC8.1'],
      recommendation: 'Implement privileged change approval workflow with audit trail',
    } : undefined,
  };
}
