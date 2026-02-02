/**
 * Privileged Account AS-REP Roastable Detector
 *
 * Detects privileged accounts (Domain Admins, Enterprise Admins, etc.)
 * without Kerberos pre-authentication - high-value targets for AS-REP roasting.
 */

import { ADUser } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../utils/entity-converter';

/**
 * Check for privileged accounts vulnerable to AS-REP Roasting
 * High-value targets (Domain Admins, Enterprise Admins, etc.) without pre-auth
 */
export function detectAdminAsrepRoastable(users: ADUser[], includeDetails: boolean): Finding {
  const privilegedGroups = [
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Administrators',
    'Account Operators',
    'Backup Operators',
    'Server Operators',
  ];

  const affected = users.filter((u) => {
    // Check for DONT_REQ_PREAUTH flag
    if (!u.userAccountControl || (u.userAccountControl & 0x400000) === 0) {
      return false;
    }
    // Check if user is in a privileged group
    if (!u.memberOf) return false;
    return u.memberOf.some((dn) =>
      privilegedGroups.some((group) => dn.toUpperCase().includes(`CN=${group.toUpperCase()}`))
    );
  });

  return {
    type: 'ADMIN_ASREP_ROASTABLE',
    severity: 'critical',
    category: 'kerberos',
    title: 'Privileged Account AS-REP Roastable',
    description:
      'Privileged accounts (Domain Admins, Enterprise Admins, etc.) without Kerberos pre-authentication. ' +
      'High-value targets for AS-REP roasting attacks - immediate domain compromise risk.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details: affected.length > 0 ? {
      risk: 'CRITICAL - Privileged account password hash can be obtained offline',
      recommendation: 'Enable Kerberos pre-authentication immediately for all privileged accounts',
    } : undefined,
  };
}
