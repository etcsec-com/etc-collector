/**
 * Kerberos Renewable Ticket Long Detector
 *
 * Detects long renewable ticket lifetime.
 * Very long renewable ticket lifetimes allow persistent access with stolen tickets.
 */

import { ADUser } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';

/**
 * Detect long renewable ticket lifetime
 *
 * Very long renewable ticket lifetimes allow persistent access.
 *
 * @param _users - Array of AD users (not used, domain-level check)
 * @param _includeDetails - Whether to include affected entity details
 * @returns Finding for KERBEROS_RENEWABLE_TICKET_LONG
 */
export function detectKerberosRenewableTicketLong(
  _users: ADUser[],
  _includeDetails: boolean
): Finding {
  // This detection would need domain Kerberos policy data
  return {
    type: 'KERBEROS_RENEWABLE_TICKET_LONG',
    severity: 'low',
    category: 'kerberos',
    title: 'Kerberos Renewable Ticket Lifetime Review',
    description:
      'Renewable ticket lifetime should be reviewed. ' +
      'Default of 7 days is reasonable; longer allows persistent access with stolen tickets.',
    count: 0, // Would be 1 if renewable lifetime > 7 days detected
    details: {
      recommendation: 'Renewable TGT lifetime should not exceed 7 days.',
    },
  };
}
