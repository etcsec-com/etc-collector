/**
 * Inactive 365 Days Detector
 * Check for inactive accounts (365+ days)
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

export function detectInactive365Days(users: ADUser[], includeDetails: boolean): Finding {
  const now = Date.now();
  const oneYearAgo = now - 365 * 24 * 60 * 60 * 1000;

  const affected = users.filter((u) => {
    if (!u.lastLogon) return false;
    return u.lastLogon.getTime() < oneYearAgo;
  });

  return {
    type: 'INACTIVE_365_DAYS',
    severity: 'medium',
    category: 'accounts',
    title: 'Inactive 365+ Days',
    description: 'User accounts inactive for 365+ days. Should be disabled or deleted.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
