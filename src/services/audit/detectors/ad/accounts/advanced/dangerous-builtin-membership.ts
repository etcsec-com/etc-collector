/**
 * Dangerous Builtin Membership Detector
 * Detect accounts in dangerous built-in groups
 *
 * Groups like Cert Publishers, RAS and IAS Servers, etc. have elevated privileges
 * that are often overlooked.
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

export function detectDangerousBuiltinMembership(users: ADUser[], includeDetails: boolean): Finding {
  const dangerousGroups = [
    'Cert Publishers', // Can publish certificates
    'RAS and IAS Servers', // Network access
    'Windows Authorization Access Group', // Token manipulation
    'Terminal Server License Servers', // Remote access
    'Incoming Forest Trust Builders', // Trust manipulation
    'Performance Log Users', // Can access performance data
    'Performance Monitor Users', // Can monitor system
    'Distributed COM Users', // DCOM access
    'Remote Desktop Users', // RDP access
    'Network Configuration Operators', // Network config
    'Cryptographic Operators', // Crypto operations
    'Event Log Readers', // Security log access
    'Hyper-V Administrators', // VM control
    'Access Control Assistance Operators', // ACL modification
    'Remote Management Users', // WinRM access
  ];

  const affected = users.filter((u) => {
    if (!u.enabled || !u.memberOf) return false;
    return u.memberOf.some((dn) =>
      dangerousGroups.some((g) => dn.toLowerCase().includes(g.toLowerCase()))
    );
  });

  return {
    type: 'DANGEROUS_BUILTIN_MEMBERSHIP',
    severity: 'medium',
    category: 'accounts',
    title: 'Dangerous Built-in Group Membership',
    description:
      'User accounts with membership in overlooked but dangerous built-in groups. ' +
      'These groups grant elevated privileges that may allow privilege escalation.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details: {
      dangerousGroups: dangerousGroups,
    },
  };
}
