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

import { Finding } from '../../../../types/finding.types';
import {
  ADCSCertificateTemplate,
  ADCSCertificateAuthority,
  CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
  CT_FLAG_PEND_ALL_REQUESTS,
  EKU_CLIENT_AUTH,
  EKU_PKIINIT_CLIENT_AUTH,
  EKU_SMART_CARD_LOGON,
  EKU_ANY_PURPOSE,
  EKU_CERTIFICATE_REQUEST_AGENT,
} from '../../../../types/adcs.types';

/**
 * Check if template allows authentication (client auth, smartcard, PKINIT)
 */
function hasAuthenticationEku(ekus: string[]): boolean {
  return (
    ekus.includes(EKU_CLIENT_AUTH) ||
    ekus.includes(EKU_PKIINIT_CLIENT_AUTH) ||
    ekus.includes(EKU_SMART_CARD_LOGON) ||
    ekus.length === 0 // No EKU = any purpose
  );
}

/**
 * ESC1: Misconfigured Certificate Template
 * Template allows enrollee to supply subject AND has client authentication EKU
 */
export function detectEsc1VulnerableTemplate(
  templates: ADCSCertificateTemplate[],
  includeDetails: boolean
): Finding {
  const affected = templates.filter((t) => {
    const nameFlag = t['msPKI-Certificate-Name-Flag'] || 0;
    const enrollmentFlag = t['msPKI-Enrollment-Flag'] || 0;
    const ekus = t.pKIExtendedKeyUsage || [];

    // Enrollee can supply subject
    const enrolleeSuppliesSubject = (nameFlag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) !== 0;

    // Has authentication capability
    const canAuthenticate = hasAuthenticationEku(ekus);

    // Doesn't require manager approval
    const noApprovalRequired = (enrollmentFlag & CT_FLAG_PEND_ALL_REQUESTS) === 0;

    return enrolleeSuppliesSubject && canAuthenticate && noApprovalRequired;
  });

  return {
    type: 'ESC1_VULNERABLE_TEMPLATE',
    severity: 'critical',
    category: 'adcs',
    title: 'ESC1 - Misconfigured Certificate Template',
    description:
      'Certificate template allows enrollee to specify Subject Alternative Name (SAN) and has client authentication EKU, enabling privilege escalation to any user/computer.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((t) => t.name || t.displayName || t.dn) : undefined,
  };
}

/**
 * ESC2: Any Purpose Certificate Template
 * Template has "Any Purpose" EKU or SubCA capability
 */
export function detectEsc2AnyPurpose(
  templates: ADCSCertificateTemplate[],
  includeDetails: boolean
): Finding {
  const affected = templates.filter((t) => {
    const ekus = t.pKIExtendedKeyUsage || [];
    const enrollmentFlag = t['msPKI-Enrollment-Flag'] || 0;

    // Has "Any Purpose" EKU
    const hasAnyPurpose = ekus.includes(EKU_ANY_PURPOSE);

    // No EKU constraint (implies any purpose)
    const noEkuConstraint = ekus.length === 0;

    // Doesn't require manager approval
    const noApprovalRequired = (enrollmentFlag & CT_FLAG_PEND_ALL_REQUESTS) === 0;

    return (hasAnyPurpose || noEkuConstraint) && noApprovalRequired;
  });

  return {
    type: 'ESC2_ANY_PURPOSE',
    severity: 'high',
    category: 'adcs',
    title: 'ESC2 - Any Purpose Certificate Template',
    description:
      'Certificate template has "Any Purpose" EKU or no EKU constraints, allowing issued certificates to be used for any purpose including client authentication.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((t) => t.name || t.displayName || t.dn) : undefined,
  };
}

/**
 * ESC3: Enrollment Agent Certificate Template
 * Template allows Certificate Request Agent (enrollment agent) certificates
 */
export function detectEsc3EnrollmentAgent(
  templates: ADCSCertificateTemplate[],
  includeDetails: boolean
): Finding {
  const affected = templates.filter((t) => {
    const ekus = t.pKIExtendedKeyUsage || [];
    const enrollmentFlag = t['msPKI-Enrollment-Flag'] || 0;

    // Has Certificate Request Agent EKU
    const hasEnrollmentAgent = ekus.includes(EKU_CERTIFICATE_REQUEST_AGENT);

    // Doesn't require manager approval
    const noApprovalRequired = (enrollmentFlag & CT_FLAG_PEND_ALL_REQUESTS) === 0;

    return hasEnrollmentAgent && noApprovalRequired;
  });

  return {
    type: 'ESC3_ENROLLMENT_AGENT',
    severity: 'high',
    category: 'adcs',
    title: 'ESC3 - Enrollment Agent Certificate Template',
    description:
      'Certificate template allows issuance of enrollment agent certificates, which can be used to enroll certificates on behalf of other users.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((t) => t.name || t.displayName || t.dn) : undefined,
  };
}

/**
 * ESC4: Vulnerable Certificate Template ACL
 * Low-privileged users can modify template properties
 * Note: Requires ACL parsing - simplified version checks if template has security descriptor
 */
export function detectEsc4VulnerableTemplateAcl(
  templates: ADCSCertificateTemplate[],
  _includeDetails: boolean
): Finding {
  // In a full implementation, this would parse nTSecurityDescriptor and check for
  // GenericAll, GenericWrite, WriteDacl, WriteOwner, or WriteProperty rights
  // for non-admin principals

  // For now, we flag templates that have authentication capability
  // and mark them as needing manual ACL review
  const affected = templates.filter((t) => {
    const ekus = t.pKIExtendedKeyUsage || [];
    return hasAuthenticationEku(ekus) && t.nTSecurityDescriptor !== undefined;
  });

  // This is a placeholder - actual implementation would analyze ACLs
  return {
    type: 'ESC4_VULNERABLE_TEMPLATE_ACL',
    severity: 'critical',
    category: 'adcs',
    title: 'ESC4 - Certificate Template ACL Review Required',
    description:
      'Certificate templates with authentication capability should be reviewed for overly permissive ACLs that allow non-admins to modify template properties.',
    count: 0, // Set to 0 until actual ACL analysis is implemented
    affectedEntities: undefined,
    details: {
      note: 'Full ACL analysis requires parsing nTSecurityDescriptor. Manual review recommended.',
      templatesWithAuthEku: affected.length,
    },
  };
}

/**
 * ESC5: PKI Object ACL Vulnerabilities
 * Vulnerable ACLs on PKI-related AD objects (CA computer, certificates container)
 * Note: This is a placeholder for ACL analysis
 */
export function detectEsc5PkiObjectAcl(
  _cas: ADCSCertificateAuthority[],
  _includeDetails: boolean
): Finding {
  // This would analyze ACLs on:
  // - CA computer object
  // - CN=Public Key Services,CN=Services,CN=Configuration
  // - CN=Enrollment Services,CN=Public Key Services,...
  // - CN=Certificate Templates,CN=Public Key Services,...

  return {
    type: 'ESC5_PKI_OBJECT_ACL',
    severity: 'medium',
    category: 'adcs',
    title: 'ESC5 - PKI Object ACL Review Required',
    description:
      'PKI-related AD objects should be reviewed for overly permissive ACLs that could allow non-admins to modify CA configuration or templates.',
    count: 0, // Placeholder until ACL analysis implemented
    affectedEntities: undefined,
    details: {
      note: 'Manual review of PKI object ACLs recommended.',
    },
  };
}

/**
 * ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 Flag
 * CA configured to allow requestor-specified SAN for any template
 * Note: This flag is in registry, not LDAP - cannot detect via pure LDAP
 */
export function detectEsc6EditfFlag(
  cas: ADCSCertificateAuthority[],
  includeDetails: boolean
): Finding {
  // EDITF_ATTRIBUTESUBJECTALTNAME2 (0x00040000) is stored in registry at:
  // HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA Name>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\EditFlags
  // Cannot be detected via LDAP alone

  return {
    type: 'ESC6_EDITF_FLAG',
    severity: 'high',
    category: 'adcs',
    title: 'ESC6 - CA Configuration Review Required',
    description:
      'Certificate Authorities should be checked for EDITF_ATTRIBUTESUBJECTALTNAME2 flag which allows any certificate requestor to specify a SAN.',
    count: 0, // Cannot detect via LDAP
    affectedEntities: includeDetails ? cas.map((ca) => ca.name || ca.dn) : undefined,
    details: {
      note: 'Check registry key EditFlags on CA servers. Flag 0x00040000 indicates vulnerability.',
      casToCheck: cas.length,
    },
  };
}

/**
 * ESC7: Vulnerable CA ACL
 * Non-admin can manage CA (ManageCA or ManageCertificates rights)
 * Note: Requires ACL parsing
 */
export function detectEsc7CaVulnerableAcl(
  cas: ADCSCertificateAuthority[],
  includeDetails: boolean
): Finding {
  // Would analyze nTSecurityDescriptor on CA enrollment objects for:
  // - ManageCA right
  // - ManageCertificates right
  // granted to non-admin principals

  return {
    type: 'ESC7_CA_VULNERABLE_ACL',
    severity: 'high',
    category: 'adcs',
    title: 'ESC7 - CA ACL Review Required',
    description:
      'Certificate Authority ACLs should be reviewed for ManageCA or ManageCertificates rights granted to non-administrators.',
    count: 0, // Placeholder until ACL analysis implemented
    affectedEntities: includeDetails ? cas.map((ca) => ca.name || ca.dn) : undefined,
    details: {
      note: 'Manual review of CA ACLs recommended.',
      casToReview: cas.length,
    },
  };
}

/**
 * ESC8: NTLM Relay to AD CS HTTP Endpoint
 * Web enrollment enabled over HTTP (allows NTLM relay attacks)
 * Note: Cannot be fully detected via LDAP - requires network probing
 */
export function detectEsc8HttpEnrollment(
  cas: ADCSCertificateAuthority[],
  includeDetails: boolean
): Finding {
  // HTTP enrollment endpoints are typically at:
  // http://<CA>/certsrv/
  // Cannot detect via LDAP alone - would need network connectivity check

  return {
    type: 'ESC8_HTTP_ENROLLMENT',
    severity: 'medium',
    category: 'adcs',
    title: 'ESC8 - Web Enrollment Check Required',
    description:
      'Certificate Authorities should be checked for HTTP-based web enrollment endpoints which are vulnerable to NTLM relay attacks.',
    count: 0, // Cannot detect via LDAP
    affectedEntities: includeDetails ? cas.map((ca) => `${ca.dNSHostName || ca.name}`) : undefined,
    details: {
      note: 'Check for http://<CA>/certsrv/ endpoints. HTTPS with Extended Protection mitigates this.',
      casToCheck: cas.length,
    },
  };
}

// ==================== PHASE 3 ESC DETECTORS ====================

/**
 * ESC9: No Security Extension (szOID_NTDS_CA_SECURITY_EXT)
 * Certificates without the new security extension are vulnerable to impersonation
 * when strong certificate mapping is not enforced.
 * Note: Requires template schema version check
 */
export function detectEsc9NoSecurityExtension(
  templates: ADCSCertificateTemplate[],
  includeDetails: boolean
): Finding {
  // Templates with schema version < 2 don't include security extension
  // msPKI-Template-Schema-Version attribute determines this
  const affected = templates.filter((t) => {
    const schemaVersion = t['msPKI-Template-Schema-Version'] || 1;
    const ekus = t.pKIExtendedKeyUsage || [];

    // Vulnerable if: old schema AND can authenticate
    return schemaVersion < 2 && hasAuthenticationEku(ekus);
  });

  return {
    type: 'ESC9_NO_SECURITY_EXTENSION',
    severity: 'high',
    category: 'adcs',
    title: 'ESC9 - No Security Extension in Certificate Template',
    description:
      'Certificate templates using schema version 1 do not include the szOID_NTDS_CA_SECURITY_EXT security extension. Combined with weak certificate mapping, this allows certificate impersonation attacks.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((t) => t.name || t.displayName || t.dn) : undefined,
    details:
      affected.length > 0
        ? {
            recommendation:
              'Upgrade certificate templates to schema version 2 or higher, and enable strong certificate mapping.',
            vulnerabilityChain: 'ESC9 + weak certificate mapping = impersonation',
          }
        : undefined,
  };
}

/**
 * ESC10: Weak Certificate Mapping
 * When strong certificate mapping is not enforced, attackers with ESC9 vulnerable
 * certificates can impersonate other users.
 * Note: This is a domain-level setting
 */
export function detectEsc10WeakCertificateMapping(
  domain: { dn: string; [key: string]: unknown } | null,
  _includeDetails: boolean
): Finding {
  // Certificate mapping strength is controlled by:
  // StrongCertificateBindingEnforcement registry key (HKLM\SYSTEM\CurrentControlSet\Services\Kdc)
  // 0 = Disabled, 1 = Compatibility mode (default), 2 = Full enforcement
  // Cannot be detected via LDAP - requires registry access

  // Also affected by CertificateMappingMethods registry key on DCs
  // UPN mapping without strong binding is vulnerable

  return {
    type: 'ESC10_WEAK_CERTIFICATE_MAPPING',
    severity: 'high',
    category: 'adcs',
    title: 'ESC10 - Certificate Mapping Configuration Review Required',
    description:
      'Domain controllers should be configured for strong certificate mapping to prevent certificate impersonation attacks. This setting cannot be detected via LDAP.',
    count: domain ? 1 : 0, // Flag as needing review if domain exists
    details: {
      note: 'Check StrongCertificateBindingEnforcement registry key on DCs. Value should be 2 (Full Enforcement).',
      registryPath:
        'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc\\StrongCertificateBindingEnforcement',
      recommendation:
        'Set StrongCertificateBindingEnforcement to 2 for full enforcement. Test in compatibility mode (1) first.',
      microsoftDoc:
        'https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers',
    },
  };
}

/**
 * ESC11: IF_ENFORCEENCRYPTICERTREQUEST Not Enforced
 * When RPC encryption is not enforced on the CA, attackers can relay NTLM
 * authentication to the CA's RPC endpoint.
 * Note: This is a CA configuration setting
 */
export function detectEsc11IcertRequestEnforcement(
  cas: ADCSCertificateAuthority[],
  includeDetails: boolean
): Finding {
  // IF_ENFORCEENCRYPTICERTREQUEST is stored in registry at:
  // HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA>\InterfaceFlags
  // Flag 0x00000200 should be set to enforce RPC encryption
  // Cannot be detected via LDAP alone

  return {
    type: 'ESC11_ICERT_REQUEST_ENFORCEMENT',
    severity: 'medium',
    category: 'adcs',
    title: 'ESC11 - RPC Encryption Enforcement Check Required',
    description:
      'Certificate Authorities should enforce RPC encryption (IF_ENFORCEENCRYPTICERTREQUEST flag) to prevent NTLM relay attacks to the ICertPassage RPC interface.',
    count: cas.length > 0 ? 1 : 0, // Flag as needing review if CAs exist
    affectedEntities: includeDetails ? cas.map((ca) => ca.name || ca.dn) : undefined,
    details: {
      note: 'Check InterfaceFlags registry key on CA servers. Flag 0x00000200 (IF_ENFORCEENCRYPTICERTREQUEST) should be set.',
      registryPath:
        'HKLM\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\<CA>\\InterfaceFlags',
      casToCheck: cas.length,
      recommendation:
        'Set IF_ENFORCEENCRYPTICERTREQUEST flag using: certutil -setreg CA\\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST',
    },
  };
}

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
