/**
 * Kerberos Security Vulnerability Detector
 *
 * Detects Kerberos-related vulnerabilities in AD.
 * Story 1.7: AD Vulnerability Detection Engine
 *
 * Vulnerabilities detected (13):
 * - ASREP_ROASTING_RISK (Critical)
 * - ADMIN_ASREP_ROASTABLE (Critical)
 * - UNCONSTRAINED_DELEGATION (Critical)
 * - GOLDEN_TICKET_RISK (Critical)
 * - KERBEROASTING_RISK (High)
 * - CONSTRAINED_DELEGATION (High)
 * - WEAK_ENCRYPTION_DES (High)
 * - KERBEROS_AES_DISABLED (High)
 * - WEAK_ENCRYPTION_RC4 (Medium)
 * - WEAK_ENCRYPTION_FLAG (Medium)
 * - KERBEROS_RC4_FALLBACK (Medium)
 * - KERBEROS_TICKET_LIFETIME_LONG (Medium)
 * - KERBEROS_RENEWABLE_TICKET_LONG (Low)
 */

import { ADUser } from '../../../../../types/ad.types';
import { Finding } from '../../../../../types/finding.types';

// Re-export all individual detectors
export { detectAsrepRoastingRisk } from './detect-asrep-roasting-risk';
export { detectUnconstrainedDelegation } from './detect-unconstrained-delegation';
export { detectGoldenTicketRisk } from './detect-golden-ticket-risk';
export { detectKerberoastingRisk } from './detect-kerberoasting-risk';
export { detectConstrainedDelegation } from './detect-constrained-delegation';
export { detectWeakEncryptionDES } from './detect-weak-encryption-des';
export { detectAdminAsrepRoastable } from './detect-admin-asrep-roastable';
export { detectWeakEncryptionRC4 } from './detect-weak-encryption-rc4';
export { detectWeakEncryptionFlag } from './detect-weak-encryption-flag';
export { detectKerberosAesDisabled } from './detect-kerberos-aes-disabled';
export { detectKerberosRc4Fallback } from './detect-kerberos-rc4-fallback';
export { detectKerberosTicketLifetimeLong } from './detect-kerberos-ticket-lifetime-long';
export { detectKerberosRenewableTicketLong } from './detect-kerberos-renewable-ticket-long';

// Import for main function
import { detectAsrepRoastingRisk } from './detect-asrep-roasting-risk';
import { detectUnconstrainedDelegation } from './detect-unconstrained-delegation';
import { detectGoldenTicketRisk } from './detect-golden-ticket-risk';
import { detectKerberoastingRisk } from './detect-kerberoasting-risk';
import { detectConstrainedDelegation } from './detect-constrained-delegation';
import { detectWeakEncryptionDES } from './detect-weak-encryption-des';
import { detectAdminAsrepRoastable } from './detect-admin-asrep-roastable';
import { detectWeakEncryptionRC4 } from './detect-weak-encryption-rc4';
import { detectWeakEncryptionFlag } from './detect-weak-encryption-flag';
import { detectKerberosAesDisabled } from './detect-kerberos-aes-disabled';
import { detectKerberosRc4Fallback } from './detect-kerberos-rc4-fallback';
import { detectKerberosTicketLifetimeLong } from './detect-kerberos-ticket-lifetime-long';
import { detectKerberosRenewableTicketLong } from './detect-kerberos-renewable-ticket-long';

/**
 * Detect all Kerberos-related vulnerabilities
 */
export function detectKerberosVulnerabilities(users: ADUser[], includeDetails: boolean): Finding[] {
  return [
    detectAsrepRoastingRisk(users, includeDetails),
    detectAdminAsrepRoastable(users, includeDetails),
    detectUnconstrainedDelegation(users, includeDetails),
    detectGoldenTicketRisk(users, includeDetails),
    detectKerberoastingRisk(users, includeDetails),
    detectConstrainedDelegation(users, includeDetails),
    detectWeakEncryptionDES(users, includeDetails),
    detectWeakEncryptionRC4(users, includeDetails),
    detectWeakEncryptionFlag(users, includeDetails),
    // Phase 4: Advanced Kerberos detections
    detectKerberosAesDisabled(users, includeDetails),
    detectKerberosRc4Fallback(users, includeDetails),
    detectKerberosTicketLifetimeLong(users, includeDetails),
    detectKerberosRenewableTicketLong(users, includeDetails),
  ].filter((finding) => finding.count > 0);
}
