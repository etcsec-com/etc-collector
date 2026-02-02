/**
 * VENDOR_ACCOUNT_UNMONITORED - Third-party accounts not monitored
 * Frameworks: DORA Art.28, ISO27001 A.15.1.1, SOC2 CC9.2
 * Detects vendor/external accounts that may lack monitoring
 */

import { ADUser } from '../../../../../../types/ad.types';
import { Finding } from '../../../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../../../utils/entity-converter';

export function detectVendorAccountUnmonitored(
  users: ADUser[],
  includeDetails: boolean
): Finding {
  // Patterns that indicate vendor/external accounts
  const vendorPatterns = [
    /vendor/i, /external/i, /contractor/i, /consultant/i,
    /partner/i, /third.?party/i, /supplier/i, /^ext[_-]/i,
    /^v[_-]/i, /^tmp[_-]/i, /^temp[_-]/i
  ];

  const vendorAccounts = users.filter((u) => {
    const name = u.sAMAccountName || '';
    const desc = (u['description'] as string) || '';
    const displayName = u.displayName || '';

    return vendorPatterns.some(p =>
      p.test(name) || p.test(desc) || p.test(displayName)
    );
  });

  // Check which vendor accounts lack monitoring indicators
  const unmonitoredVendors = vendorAccounts.filter((u) => {
    // Check for account expiration (vendors should have expiry)
    const accountExpires = u['accountExpires'] as Date | bigint | number | undefined;
    let hasExpiry = false;
    if (accountExpires) {
      if (typeof accountExpires === 'bigint') {
        // Never expires: 9223372036854775807 or 0
        hasExpiry = accountExpires !== BigInt('9223372036854775807') && accountExpires !== BigInt(0);
      } else if (typeof accountExpires === 'number') {
        hasExpiry = accountExpires !== 9223372036854775807 && accountExpires !== 0;
      } else if (accountExpires instanceof Date) {
        hasExpiry = accountExpires.getTime() > Date.now();
      }
    }

    // Check for recent activity
    const lastLogon = u.lastLogon;
    const NINETY_DAYS_MS = 90 * 24 * 60 * 60 * 1000;
    const isActive = lastLogon && (Date.now() - lastLogon.getTime()) < NINETY_DAYS_MS;

    // Flag if no expiry AND active (should be monitored)
    return !hasExpiry && isActive;
  });

  return {
    type: 'VENDOR_ACCOUNT_UNMONITORED',
    severity: 'medium',
    category: 'compliance',
    title: 'Vendor Accounts Not Properly Monitored',
    description:
      'Third-party/vendor accounts detected without proper expiration or monitoring controls. Required by DORA Article 28, ISO27001 A.15.1.1, SOC2 CC9.2.',
    count: unmonitoredVendors.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(unmonitoredVendors.slice(0, 50)) : undefined,
    details: unmonitoredVendors.length > 0 ? {
      totalVendorAccounts: vendorAccounts.length,
      unmonitoredCount: unmonitoredVendors.length,
      frameworks: ['DORA', 'ISO27001', 'SOC2'],
      controls: ['Art.28', 'A.15.1.1', 'CC9.2'],
      recommendation: 'Set expiration dates and enable enhanced logging for all vendor accounts',
    } : undefined,
  };
}
