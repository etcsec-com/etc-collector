/**
 * WRITESPN_ABUSE - WriteProperty permission for servicePrincipalName
 */

import { AclEntry } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { getUniqueObjects } from '../utils';

/**
 * Check for WriteProperty permission for servicePrincipalName
 */
export function detectWriteSpnAbuse(aclEntries: AclEntry[], includeDetails: boolean): Finding {
  const SPN_PROPERTY_GUID = 'f3a64788-5306-11d1-a9c5-0000f80367c1';

  const affected = aclEntries.filter((ace) => {
    return ace.objectType === SPN_PROPERTY_GUID;
  });

  const uniqueObjects = getUniqueObjects(affected);
  const totalInstances = affected.length;

  return {
    type: 'WRITESPN_ABUSE',
    severity: 'medium',
    category: 'permissions',
    title: 'Write SPN Abuse',
    description: 'WriteProperty permission for servicePrincipalName attribute. Can set SPNs for targeted Kerberoasting.',
    count: uniqueObjects.length,
    totalInstances: totalInstances !== uniqueObjects.length ? totalInstances : undefined,
    affectedEntities: includeDetails ? uniqueObjects : undefined,
  };
}
