/**
 * Password In Description Detector
 *
 * Detects user accounts with passwords or password-like strings in the description field.
 * Cleartext credential exposure.
 */

import { ADUser } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';
import { toAffectedUserEntities, ldapAttrToString } from '../../../../../utils/entity-converter';

/**
 * Check if password is in description field
 */
export function detectPasswordInDescription(users: ADUser[], includeDetails: boolean): Finding {
  const passwordPatterns = [
    /password\s*[:=]\s*\S+/i,
    /pwd\s*[:=]\s*\S+/i,
    /pass\s*[:=]\s*\S+/i,
    /motdepasse\s*[:=]\s*\S+/i,
    /\bP@ssw0rd\b/i,
    /\bPassword123\b/i,
  ];

  const affected = users.filter((u) => {
    const description = ldapAttrToString((u as any)['description']);
    if (!description) return false;
    return passwordPatterns.some((pattern) => pattern.test(description));
  });

  return {
    type: 'PASSWORD_IN_DESCRIPTION',
    severity: 'high',
    category: 'passwords',
    title: 'Password in Description',
    description: 'User accounts with passwords or password-like strings in the description field. Cleartext credential exposure.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
