/**
 * Test Account Detector
 * Check for test accounts
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

export function detectTestAccount(users: ADUser[], includeDetails: boolean): Finding {
  const testPatterns = [/^test/i, /test$/i, /_test/i, /\.test/i, /^demo/i, /^temp/i];

  const affected = users.filter((u) => {
    return testPatterns.some((pattern) => pattern.test(u.sAMAccountName));
  });

  return {
    type: 'TEST_ACCOUNT',
    severity: 'medium',
    category: 'accounts',
    title: 'Test Account',
    description: 'User accounts with test/demo/temp naming. Should be removed from production.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
