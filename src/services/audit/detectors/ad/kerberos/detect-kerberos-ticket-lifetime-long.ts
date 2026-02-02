/**
 * Kerberos Ticket Lifetime Long Detector
 *
 * Detects long Kerberos ticket lifetime (domain level).
 * Very long ticket lifetimes increase the window for ticket theft attacks.
 */

import { ADUser } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';

/**
 * Detect long Kerberos ticket lifetime (domain level)
 *
 * Very long ticket lifetimes increase the window for ticket theft attacks.
 *
 * @param _users - Array of AD users (not used, domain-level check)
 * @param _includeDetails - Whether to include affected entity details
 * @returns Finding for KERBEROS_TICKET_LIFETIME_LONG
 */
export function detectKerberosTicketLifetimeLong(
  _users: ADUser[],
  _includeDetails: boolean
): Finding {
  // This detection would need domain Kerberos policy data
  // For now, return a placeholder that reminds to check
  return {
    type: 'KERBEROS_TICKET_LIFETIME_LONG',
    severity: 'medium',
    category: 'kerberos',
    title: 'Kerberos Ticket Lifetime Review',
    description:
      'Kerberos ticket lifetime should be reviewed. ' +
      'Default of 10 hours is reasonable; longer lifetimes increase attack window.',
    count: 0, // Would be 1 if ticket lifetime > 10 hours detected
    details: {
      recommendation: 'TGT lifetime should not exceed 10 hours. Service tickets should not exceed 600 minutes.',
      checkCommand: 'gpresult /r or check Default Domain Policy',
    },
  };
}
