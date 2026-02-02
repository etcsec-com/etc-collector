/**
 * PRIVILEGED_ACCESS_REVIEW_MISSING - No recent access review
 * Frameworks: SOX Section 404, ISO27001 A.9.2.5, SOC2 CC6.2
 * Checks if privileged group membership has been reviewed recently
 */

import { ADUser, ADGroup } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';

export function detectPrivilegedAccessReviewMissing(
  users: ADUser[],
  groups: ADGroup[],
  _includeDetails: boolean
): Finding {
  const issues: string[] = [];
  const NINETY_DAYS_MS = 90 * 24 * 60 * 60 * 1000;
  const now = Date.now();

  const privilegedGroupNames = ['Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators'];

  // Check privileged groups for stale membership
  for (const group of groups) {
    if (!privilegedGroupNames.some(pg => group.sAMAccountName?.toLowerCase() === pg.toLowerCase())) {
      continue;
    }

    // Check whenChanged on group (indicates membership review)
    const groupChanged = group['whenChanged'] as Date | undefined;
    if (groupChanged && (now - groupChanged.getTime()) > NINETY_DAYS_MS) {
      // Group not modified in 90 days - may indicate no access review
      const memberCount = group.member?.length || 0;
      if (memberCount > 0) {
        issues.push(`${group.sAMAccountName} (${memberCount} members) not reviewed in 90+ days`);
      }
    }
  }

  // Check for admin accounts with very old last logon (may be orphaned)
  const privilegedUsers = users.filter((u) => {
    if (!u.memberOf) return false;
    return u.memberOf.some((dn) => privilegedGroupNames.some((pg) => dn.includes(`CN=${pg}`)));
  });

  const staleAdmins = privilegedUsers.filter((u) => {
    if (!u.lastLogon) return true; // Never logged on
    return (now - u.lastLogon.getTime()) > NINETY_DAYS_MS;
  });

  if (staleAdmins.length > 0) {
    issues.push(`${staleAdmins.length} privileged accounts inactive for 90+ days`);
  }

  return {
    type: 'PRIVILEGED_ACCESS_REVIEW_MISSING',
    severity: 'medium',
    category: 'compliance',
    title: 'Privileged Access Review Missing',
    description:
      'Privileged access has not been reviewed recently. Required by SOX Section 404, ISO27001 A.9.2.5, SOC2 CC6.2.',
    count: issues.length > 0 ? 1 : 0,
    details: issues.length > 0 ? {
      violations: issues,
      frameworks: ['SOX', 'ISO27001', 'SOC2'],
      controls: ['Section 404', 'A.9.2.5', 'CC6.2'],
      recommendation: 'Implement quarterly privileged access reviews with documented approval',
    } : undefined,
  };
}
