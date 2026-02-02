/**
 * ADCS Security Vulnerability Detector
 *
 * Detects ESC1-ESC11 vulnerabilities in AD Certificate Services.
 *
 * Vulnerabilities detected (11):
 * CRITICAL (2):
 * - ESC1_VULNERABLE_TEMPLATE: Template allows enrollee to supply SAN + has client auth
 * - ESC4_VULNERABLE_TEMPLATE_ACL: Non-admin can modify vulnerable template
 *
 * HIGH (6):
 * - ESC2_ANY_PURPOSE: Template has "Any Purpose" EKU
 * - ESC3_ENROLLMENT_AGENT: Template allows enrollment agent certificate
 * - ESC6_EDITF_FLAG: CA allows requestor-specified SAN (registry flag)
 * - ESC7_CA_VULNERABLE_ACL: Non-admin can manage CA
 * - ESC9_NO_SECURITY_EXTENSION: No security extension in certificates (Phase 3)
 * - ESC10_WEAK_CERTIFICATE_MAPPING: Weak certificate mapping configured (Phase 3)
 *
 * MEDIUM (3):
 * - ESC5_PKI_OBJECT_ACL: Vulnerable PKI object ACLs
 * - ESC8_HTTP_ENROLLMENT: HTTP web enrollment (NTLM relay risk)
 * - ESC11_ICERT_REQUEST_ENFORCEMENT: IF_ENFORCEENCRYPTICERTREQUEST disabled (Phase 3)
 */

import { Finding } from '../../../../../types/finding.types';
import {
  ADCSCertificateTemplate,
  ADCSCertificateAuthority,
} from '../../../../../types/adcs.types';

// Re-export utilities
export { hasAuthenticationEku } from './utils';

// Re-export individual detectors
export { detectEsc1VulnerableTemplate } from './esc1.detector';
export { detectEsc2AnyPurpose } from './esc2.detector';
export { detectEsc3EnrollmentAgent } from './esc3.detector';
export { detectEsc4VulnerableTemplateAcl } from './esc4.detector';
export { detectEsc5PkiObjectAcl } from './esc5.detector';
export { detectEsc6EditfFlag } from './esc6.detector';
export { detectEsc7CaVulnerableAcl } from './esc7.detector';
export { detectEsc8HttpEnrollment } from './esc8.detector';
export { detectEsc9NoSecurityExtension } from './esc9.detector';
export { detectEsc10WeakCertificateMapping } from './esc10.detector';
export { detectEsc11IcertRequestEnforcement } from './esc11.detector';

// Import for aggregate function
import { detectEsc1VulnerableTemplate } from './esc1.detector';
import { detectEsc2AnyPurpose } from './esc2.detector';
import { detectEsc3EnrollmentAgent } from './esc3.detector';
import { detectEsc4VulnerableTemplateAcl } from './esc4.detector';
import { detectEsc5PkiObjectAcl } from './esc5.detector';
import { detectEsc6EditfFlag } from './esc6.detector';
import { detectEsc7CaVulnerableAcl } from './esc7.detector';
import { detectEsc8HttpEnrollment } from './esc8.detector';
import { detectEsc9NoSecurityExtension } from './esc9.detector';
import { detectEsc10WeakCertificateMapping } from './esc10.detector';
import { detectEsc11IcertRequestEnforcement } from './esc11.detector';

/**
 * Aggregate function: Detect all ADCS vulnerabilities
 */
export function detectAdcsVulnerabilities(
  templates: ADCSCertificateTemplate[],
  cas: ADCSCertificateAuthority[],
  includeDetails: boolean,
  domain?: { dn: string; [key: string]: unknown } | null
): Finding[] {
  return [
    detectEsc1VulnerableTemplate(templates, includeDetails),
    detectEsc2AnyPurpose(templates, includeDetails),
    detectEsc3EnrollmentAgent(templates, includeDetails),
    detectEsc4VulnerableTemplateAcl(templates, includeDetails),
    detectEsc5PkiObjectAcl(cas, includeDetails),
    detectEsc6EditfFlag(cas, includeDetails),
    detectEsc7CaVulnerableAcl(cas, includeDetails),
    detectEsc8HttpEnrollment(cas, includeDetails),
    // Phase 3: ESC9-ESC11
    detectEsc9NoSecurityExtension(templates, includeDetails),
    detectEsc10WeakCertificateMapping(domain || null, includeDetails),
    detectEsc11IcertRequestEnforcement(cas, includeDetails),
  ].filter((finding) => finding.count > 0 || finding.details?.['note']);
}
