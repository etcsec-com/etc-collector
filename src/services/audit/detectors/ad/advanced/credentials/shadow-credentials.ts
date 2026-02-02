/**
 * Shadow Credentials Detector
 * Check for Shadow Credentials attack (msDS-KeyCredentialLink)
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

export function detectShadowCredentials(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    const keyLink = (u as any)['msDS-KeyCredentialLink'];
    // Check that attribute exists, is not null, not empty string, and not empty array
    return keyLink && (Array.isArray(keyLink) ? keyLink.length > 0 : keyLink !== '');
  });

  return {
    type: 'SHADOW_CREDENTIALS',
    severity: 'critical',
    category: 'advanced',
    title: 'Shadow Credentials',
    description: 'msDS-KeyCredentialLink attribute configured. Allows Kerberos authentication bypass by adding arbitrary public keys.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
