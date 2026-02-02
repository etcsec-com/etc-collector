/**
 * Unix User Password Detector
 *
 * Detects user accounts with Unix password attributes present.
 * These may contain cleartext or weakly hashed passwords.
 */

import { ADUser } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../utils/entity-converter';

/**
 * Check for Unix password attributes (cleartext)
 */
export function detectUnixUserPassword(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    // Check for unixUserPassword or userPassword attributes
    return 'unixUserPassword' in u || 'userPassword' in u;
  });

  return {
    type: 'UNIX_USER_PASSWORD',
    severity: 'critical',
    category: 'passwords',
    title: 'Unix User Password',
    description: 'User accounts with Unix password attributes present. These may contain cleartext or weakly hashed passwords.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
