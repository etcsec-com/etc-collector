/**
 * CIS Network Security (2.3.7.x)
 * Checks CIS Benchmark network security settings
 */

import { Finding } from '../../../../../../types/finding.types';
import { GpoSecuritySettings } from '../../../../../../providers/smb/smb.provider';

export function detectCisNetworkSecurity(
  gpoSettings: GpoSecuritySettings | null,
  _includeDetails: boolean
): Finding {
  const issues: string[] = [];

  if (gpoSettings) {
    // Check SMBv1
    if (gpoSettings.smbv1ServerEnabled || gpoSettings.smbv1ClientEnabled) {
      issues.push('SMBv1 enabled (CIS 2.3.7.1 - Disable SMBv1)');
    }

    // Check LDAP signing
    if (gpoSettings.ldapServerIntegrity !== undefined && gpoSettings.ldapServerIntegrity < 2) {
      issues.push('LDAP signing not required (CIS 2.3.7.2)');
    }

    // Check LDAP channel binding
    if (gpoSettings.ldapChannelBinding !== undefined && gpoSettings.ldapChannelBinding < 2) {
      issues.push('LDAP channel binding not required (CIS 2.3.7.3)');
    }
  } else {
    issues.push('GPO settings not available for network security analysis');
  }

  return {
    type: 'CIS_NETWORK_SECURITY',
    severity: 'medium',
    category: 'compliance',
    title: 'CIS Benchmark - Network Security Non-Compliant',
    description:
      'Network security settings do not meet CIS Benchmark recommendations. SMBv1 should be disabled, LDAP signing required.',
    count: issues.length > 0 ? 1 : 0,
    details: issues.length > 0 ? { violations: issues, framework: 'CIS', control: '2.3.7.x' } : undefined,
  };
}
