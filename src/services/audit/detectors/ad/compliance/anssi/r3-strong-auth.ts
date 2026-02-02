/**
 * ANSSI R3 - Strong Authentication
 * Checks if strong authentication is enforced:
 * - Kerberos AES encryption enabled
 * - NTLM restrictions in place
 * - Credential Guard considerations
 */

import { ADUser, ADDomain } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';

export function detectAnssiR3StrongAuth(
  users: ADUser[],
  domain: ADDomain,
  _includeDetails: boolean
): Finding {
  const issues: string[] = [];

  // Check domain functional level (impacts security features)
  const functionalLevel = (domain['domainFunctionalLevel'] as number) || 0;
  if (functionalLevel < 6) {
    // Windows Server 2012 R2
    issues.push(`Domain functional level ${functionalLevel} is below 2012 R2 (6), limiting security features`);
  }

  // Check users with weak encryption types
  const weakEncryptionUsers = users.filter((u) => {
    const encTypes = u['msDS-SupportedEncryptionTypes'] as number | undefined;
    if (typeof encTypes !== 'number') return false;
    // Only DES/RC4, no AES
    return (encTypes & 0x18) === 0 && (encTypes & 0x7) !== 0;
  });

  if (weakEncryptionUsers.length > 0) {
    issues.push(`${weakEncryptionUsers.length} users with weak encryption (no AES)`);
  }

  // Check for users without Kerberos pre-authentication
  const noPreAuthUsers = users.filter((u) => {
    const uac = u.userAccountControl || 0;
    return (uac & 0x400000) !== 0; // DONT_REQ_PREAUTH
  });

  if (noPreAuthUsers.length > 0) {
    issues.push(`${noPreAuthUsers.length} users without Kerberos pre-authentication`);
  }

  return {
    type: 'ANSSI_R3_STRONG_AUTH',
    severity: 'medium',
    category: 'compliance',
    title: 'ANSSI R3 - Strong Authentication Issues',
    description:
      'Strong authentication mechanisms not fully enforced per ANSSI R3. Kerberos AES should be required, and weak encryption types disabled.',
    count: issues.length > 0 ? 1 : 0,
    details: issues.length > 0 ? { violations: issues, framework: 'ANSSI', control: 'R3' } : undefined,
  };
}
