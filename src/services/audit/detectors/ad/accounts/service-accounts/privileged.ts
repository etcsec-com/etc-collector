/**
 * Service Account Privileged Detector
 * SERVICE_ACCOUNT_PRIVILEGED: Service accounts in privileged groups
 * Critical - service accounts should not be domain admins
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';
import { isServiceAccount } from './utils';

export function detectServiceAccountPrivileged(users: ADUser[], includeDetails: boolean): Finding {
  const privilegedGroups = [
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Administrators',
    'Backup Operators',
    'Account Operators',
    'Server Operators',
  ];

  const affected = users.filter((u) => {
    // Must be a service account
    if (!isServiceAccount(u)) return false;
    // Must be enabled
    if (u.userAccountControl && (u.userAccountControl & 0x2) !== 0) return false;
    // Check if in privileged groups
    if (!u.memberOf) return false;
    return u.memberOf.some((dn) => privilegedGroups.some((group) => dn.includes(`CN=${group}`)));
  });

  return {
    type: 'SERVICE_ACCOUNT_PRIVILEGED',
    severity: 'critical',
    category: 'accounts',
    title: 'Service Account in Privileged Group',
    description:
      'Service accounts with membership in privileged groups (Domain Admins, etc.). If compromised, attackers gain full domain control.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details:
      affected.length > 0
        ? {
            recommendation:
              'Remove service accounts from privileged groups. Grant only the minimum permissions needed for the service to function.',
          }
        : undefined,
  };
}
