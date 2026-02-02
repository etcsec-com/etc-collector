/**
 * Password Common Patterns Detector
 *
 * Detects accounts with names suggesting default/weak passwords.
 * These accounts are primary targets for password spraying attacks.
 *
 * Phase 3 addition.
 */

import { ADUser } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../utils/entity-converter';

/**
 * Check for common password patterns in account names
 *
 * Accounts with names suggesting default/weak passwords.
 *
 * @param users - Array of AD users
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for PASSWORD_COMMON_PATTERNS
 */
export function detectPasswordCommonPatterns(users: ADUser[], includeDetails: boolean): Finding {
  // Patterns that suggest default or weak passwords
  const riskyNamePatterns = [
    /^admin$/i,
    /^administrator$/i,
    /^test$/i,
    /^user$/i,
    /^guest$/i,
    /^temp$/i,
    /^default$/i,
    /^support$/i,
    /^service$/i,
    /^backup$/i,
    /^demo$/i,
    /password/i,
    /123$/,
    /^sa$/i,
    /^dba$/i,
  ];

  const affected = users.filter((u) => {
    if (!u.enabled) return false;
    const samName = u.sAMAccountName.toLowerCase();
    return riskyNamePatterns.some((pattern) => pattern.test(samName));
  });

  return {
    type: 'PASSWORD_COMMON_PATTERNS',
    severity: 'high',
    category: 'passwords',
    title: 'Common Password Pattern Risk',
    description:
      'User accounts with names suggesting default or commonly-used passwords (admin, test, user, temp). ' +
      'These accounts are primary targets for password spraying attacks.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details: {
      affectedAccountNames: affected.slice(0, 10).map((u) => u.sAMAccountName),
    },
  };
}
