/**
 * Password Cleartext Storage Detector
 *
 * Detects accounts with attributes that may store passwords in cleartext
 * or reversible format (supplementalCredentials, userPassword, etc.)
 *
 * Phase 3 addition.
 */

import { ADUser } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../utils/entity-converter';

/**
 * Check for cleartext password storage attributes
 *
 * Detects accounts with attributes that may store passwords in cleartext
 * or reversible format (supplementalCredentials, userPassword, etc.)
 *
 * @param users - Array of AD users
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for PASSWORD_CLEARTEXT_STORAGE
 */
export function detectPasswordCleartextStorage(users: ADUser[], includeDetails: boolean): Finding {
  const cleartextAttributes = [
    'unixUserPassword',
    'userPassword',
    'unicodePwd', // Should never be readable
    'msDS-ManagedPassword', // gMSA - should be protected
    'ms-Mcs-AdmPwd', // LAPS - cleartext by design, but should be protected
  ];

  const affected = users.filter((u) => {
    // Check if any cleartext password attribute exists and has a value
    return cleartextAttributes.some((attr) => {
      const value = (u as Record<string, unknown>)[attr];
      return value !== undefined && value !== null && value !== '';
    });
  });

  return {
    type: 'PASSWORD_CLEARTEXT_STORAGE',
    severity: 'critical',
    category: 'passwords',
    title: 'Cleartext Password Storage',
    description:
      'User accounts with attributes that may store passwords in cleartext or reversible format. ' +
      'These attributes (userPassword, unixUserPassword) can be read by attackers with LDAP access.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}
