/**
 * dsHeuristics Modified Detector
 * Detect modified dsHeuristics attribute
 *
 * dsHeuristics controls various AD behaviors. Non-default values may indicate
 * security weakening (e.g., allowing anonymous access, disabling list object mode).
 */

import { ADDomain } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';

export function detectDsHeuristicsModified(
  domain: ADDomain | null,
  _includeDetails: boolean
): Finding {
  // dsHeuristics is stored on CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration
  const dsHeuristics = domain ? (domain as Record<string, unknown>)['dsHeuristics'] as string | undefined : undefined;

  // Default is empty or null - any value is a modification
  const isModified = dsHeuristics !== undefined && dsHeuristics !== null && dsHeuristics !== '';

  // Check for specific dangerous settings
  const dangerousSettings: string[] = [];
  if (dsHeuristics) {
    // Position 7: fLDAPBlockAnonOps (0=block anonymous, 2=allow)
    if (dsHeuristics.length >= 7 && dsHeuristics[6] === '2') {
      dangerousSettings.push('Anonymous LDAP operations allowed (position 7)');
    }
    // Position 3: fDisableListObject (0=enabled, 1=disabled)
    if (dsHeuristics.length >= 3 && dsHeuristics[2] === '1') {
      dangerousSettings.push('List Object mode disabled (position 3)');
    }
  }

  return {
    type: 'DS_HEURISTICS_MODIFIED',
    severity: 'medium',
    category: 'advanced',
    title: 'dsHeuristics Modified',
    description:
      'The dsHeuristics attribute has been modified from defaults. ' +
      'This may weaken AD security or enable dangerous features.',
    count: isModified ? 1 : 0,
    details: {
      currentValue: dsHeuristics || '(empty)',
      dangerousSettings: dangerousSettings.length > 0 ? dangerousSettings : undefined,
      recommendation:
        'Review dsHeuristics value and document any intentional modifications.',
    },
  };
}
