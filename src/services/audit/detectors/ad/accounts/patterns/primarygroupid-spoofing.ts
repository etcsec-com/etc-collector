/**
 * PrimaryGroupID Spoofing Detector
 * Check for primaryGroupID spoofing
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

export function detectPrimaryGroupIdSpoofing(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    const primaryGroupId = (u as any).primaryGroupID;
    if (!primaryGroupId) return false;
    return primaryGroupId !== 513;
  });

  return {
    type: 'PRIMARYGROUPID_SPOOFING',
    severity: 'medium',
    category: 'accounts',
    title: 'primaryGroupID Spoofing',
    description: 'User accounts with non-standard primaryGroupID. Can be used to hide group membership.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
