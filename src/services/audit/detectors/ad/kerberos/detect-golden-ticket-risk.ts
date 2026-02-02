/**
 * Golden Ticket Risk Detector
 *
 * Detects when the krbtgt account password is old (180+ days).
 * Old krbtgt passwords enable persistent Golden Ticket attacks.
 */

import { ADUser } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';

/**
 * Check for Golden Ticket risk (krbtgt password old)
 */
export function detectGoldenTicketRisk(users: ADUser[], includeDetails: boolean): Finding {
  const krbtgtAccount = users.find((u) => u.sAMAccountName === 'krbtgt');

  if (!krbtgtAccount || !krbtgtAccount.passwordLastSet) {
    return {
      type: 'GOLDEN_TICKET_RISK',
      severity: 'critical',
      category: 'kerberos',
      title: 'Golden Ticket Risk',
      description: 'krbtgt account password unchanged for 180+ days or password date unavailable. Enables persistent Golden Ticket attacks.',
      count: 0,
    };
  }

  const now = Date.now();
  const sixMonthsAgo = now - 180 * 24 * 60 * 60 * 1000;
  const passwordAge = krbtgtAccount.passwordLastSet.getTime();
  const isOld = passwordAge < sixMonthsAgo;

  return {
    type: 'GOLDEN_TICKET_RISK',
    severity: 'critical',
    category: 'kerberos',
    title: 'Golden Ticket Risk',
    description: `krbtgt account password unchanged for 180+ days. Enables persistent Golden Ticket attacks.`,
    count: isOld ? 1 : 0,
    affectedEntities: includeDetails && isOld ? [krbtgtAccount.dn] : undefined,
  };
}
