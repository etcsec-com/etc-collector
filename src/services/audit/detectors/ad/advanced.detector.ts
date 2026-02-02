/**
 * Advanced Security Vulnerability Detector
 *
 * Detects advanced AD vulnerabilities including ADCS, LAPS, Shadow Credentials, RBCD, DCSync, etc.
 * Story 1.7: AD Vulnerability Detection Engine
 * Story 1.1: SMB & LDAP Signing Detection
 *
 * Vulnerabilities detected (36):
 * CRITICAL (5):
 * - SHADOW_CREDENTIALS
 * - RBCD_ABUSE
 * - EXCHANGE_PRIV_ESC_PATH - Phase 4
 * - LDAP_SIGNING_DISABLED - LDAP signing not required (Story 1.1)
 * - SMB_SIGNING_DISABLED - SMB signing not required (Story 1.1)
 *
 * HIGH (11):
 * - ESC1_VULNERABLE_TEMPLATE
 * - ESC2_ANY_PURPOSE
 * - ESC3_ENROLLMENT_AGENT
 * - ESC4_VULNERABLE_TEMPLATE_ACL
 * - ESC6_EDITF_ATTRIBUTESUBJECTALTNAME2
 * - LAPS_PASSWORD_READABLE
 * - REPLICATION_RIGHTS
 * - DCSYNC_CAPABLE
 * - MACHINE_ACCOUNT_QUOTA_HIGH - Quota > 10 (intentionally increased)
 * - LDAP_CHANNEL_BINDING_DISABLED - LDAP channel binding not required
 * - SMB_V1_ENABLED - SMBv1 protocol enabled
 * - ADMIN_SD_HOLDER_MODIFIED - Phase 4
 *
 * MEDIUM (17):
 * - ESC8_HTTP_ENROLLMENT
 * - LAPS_NOT_DEPLOYED
 * - LAPS_LEGACY_ATTRIBUTE
 * - DUPLICATE_SPN
 * - WEAK_PASSWORD_POLICY
 * - WEAK_KERBEROS_POLICY
 * - MACHINE_ACCOUNT_QUOTA_ABUSE
 * - DELEGATION_PRIVILEGE
 * - ADCS_WEAK_PERMISSIONS
 * - DANGEROUS_LOGON_SCRIPTS
 * - FOREIGN_SECURITY_PRINCIPALS
 * - NTLM_RELAY_OPPORTUNITY
 * - RECYCLE_BIN_DISABLED - AD Recycle Bin not enabled
 * - ANONYMOUS_LDAP_ACCESS - Anonymous LDAP bind allowed
 * - AUDIT_POLICY_WEAK - Audit policy incomplete
 * - POWERSHELL_LOGGING_DISABLED - PowerShell logging not configured
 * - DS_HEURISTICS_MODIFIED - Phase 4
 *
 * LOW (2):
 * - LAPS_PASSWORD_SET
 * - LAPS_PASSWORD_LEAKED
 */

import { ADUser, ADComputer, ADDomain } from '../../../../types/ad.types';
import { Finding } from '../../../../types/finding.types';
import { toAffectedUserEntities } from '../../../../utils/entity-converter';

/**
 * Check for Shadow Credentials attack (msDS-KeyCredentialLink)
 */
export function detectShadowCredentials(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    const keyLink = (u as any)['msDS-KeyCredentialLink'];
    // Check that attribute exists, is not null, not empty string, and not empty array
    return keyLink && (Array.isArray(keyLink) ? keyLink.length > 0 : keyLink !== '');
  });

  return {
    type: 'SHADOW_CREDENTIALS',
    severity: 'critical',
    category: 'advanced',
    title: 'Shadow Credentials',
    description: 'msDS-KeyCredentialLink attribute configured. Allows Kerberos authentication bypass by adding arbitrary public keys.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check for RBCD abuse (Resource-Based Constrained Delegation)
 */
export function detectRbcdAbuse(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    const rbcdAttr = (u as any)['msDS-AllowedToActOnBehalfOfOtherIdentity'];
    // Check that attribute exists, is not null, not empty string, and not empty array
    return rbcdAttr && (Array.isArray(rbcdAttr) ? rbcdAttr.length > 0 : rbcdAttr !== '');
  });

  return {
    type: 'RBCD_ABUSE',
    severity: 'critical',
    category: 'advanced',
    title: 'RBCD Abuse',
    description: 'msDS-AllowedToActOnBehalfOfOtherIdentity configured. Enables privilege escalation via resource-based delegation.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check for ESC1 vulnerable certificate template
 */
export function detectEsc1VulnerableTemplate(templates: any[], includeDetails: boolean): Finding {
  const affected = templates.filter((t) => {
    const hasClientAuth = t.pKIExtendedKeyUsage?.includes('1.3.6.1.5.5.7.3.2');
    const enrolleeSuppliesSubject = t['msPKI-Certificate-Name-Flag'] && (t['msPKI-Certificate-Name-Flag'] & 0x1) !== 0;
    return hasClientAuth && enrolleeSuppliesSubject;
  });

  return {
    type: 'ESC1_VULNERABLE_TEMPLATE',
    severity: 'high',
    category: 'advanced',
    title: 'ESC1 Vulnerable Template',
    description: 'ADCS template with client auth + enrollee supplies subject. Enables domain compromise by obtaining cert for any user.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((t) => t.dn) : undefined,
  };
}

/**
 * Check for ESC2 Any Purpose EKU
 */
export function detectEsc2AnyPurpose(templates: any[], includeDetails: boolean): Finding {
  const affected = templates.filter((t) => {
    const hasAnyPurpose = t.pKIExtendedKeyUsage?.includes('2.5.29.37.0');
    const isEmpty = !t.pKIExtendedKeyUsage || t.pKIExtendedKeyUsage.length === 0;
    return hasAnyPurpose || isEmpty;
  });

  return {
    type: 'ESC2_ANY_PURPOSE',
    severity: 'high',
    category: 'advanced',
    title: 'ESC2 Any Purpose',
    description: 'ADCS template with Any Purpose EKU or no usage restriction. Certificate can be used for domain authentication.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((t) => t.dn) : undefined,
  };
}

/**
 * Check for ESC3 enrollment agent
 */
export function detectEsc3EnrollmentAgent(templates: any[], includeDetails: boolean): Finding {
  const affected = templates.filter((t) => {
    return t.pKIExtendedKeyUsage?.includes('1.3.6.1.4.1.311.20.2.1');
  });

  return {
    type: 'ESC3_ENROLLMENT_AGENT',
    severity: 'high',
    category: 'advanced',
    title: 'ESC3 Enrollment Agent',
    description: 'ADCS template with enrollment agent EKU. Can request certificates on behalf of other users.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((t) => t.dn) : undefined,
  };
}

/**
 * Check for ESC4 vulnerable template ACL
 */
export function detectEsc4VulnerableTemplateAcl(templates: any[], includeDetails: boolean): Finding {
  const affected = templates.filter((t) => {
    return t.hasWeakAcl; // This would be populated by ACL analysis
  });

  return {
    type: 'ESC4_VULNERABLE_TEMPLATE_ACL',
    severity: 'high',
    category: 'advanced',
    title: 'ESC4 Vulnerable Template ACL',
    description: 'Certificate template with weak ACLs. Can modify template to make it vulnerable to ESC1/ESC2.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((t) => t.dn) : undefined,
  };
}

/**
 * Check for ESC6 EDITF_ATTRIBUTESUBJECTALTNAME2
 */
export function detectEsc6EditfAttributeSubjectAltName2(cas: any[], includeDetails: boolean): Finding {
  const affected = cas.filter((ca) => {
    return ca.flags && (ca.flags & 0x40000) !== 0; // EDITF_ATTRIBUTESUBJECTALTNAME2
  });

  return {
    type: 'ESC6_EDITF_ATTRIBUTESUBJECTALTNAME2',
    severity: 'high',
    category: 'advanced',
    title: 'ESC6 EDITF Flag',
    description: 'ADCS CA with EDITF_ATTRIBUTESUBJECTALTNAME2 flag. Allows specifying arbitrary SAN in certificate requests.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((ca) => ca.dn) : undefined,
  };
}

/**
 * Check for LAPS password readable by non-admins
 */
export function detectLapsPasswordReadable(computers: ADComputer[], includeDetails: boolean): Finding {
  const affected = computers.filter((c) => {
    return (c as any).lapsPasswordReadableByNonAdmins; // This would be populated by ACL analysis
  });

  return {
    type: 'LAPS_PASSWORD_READABLE',
    severity: 'high',
    category: 'advanced',
    title: 'LAPS Password Readable',
    description: 'Non-admin users can read LAPS password attributes. Exposure of local admin passwords.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((c) => c.dn) : undefined,
  };
}

/**
 * Check for accounts with replication rights (potential DCSync)
 */
export function detectReplicationRights(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    // adminCount=1 but not in standard admin groups
    if (u.adminCount !== 1) return false;
    if (!u.memberOf) return true; // Has adminCount but no groups

    const isInStandardAdminGroups = u.memberOf.some((dn) => {
      return (
        dn.includes('CN=Domain Admins') ||
        dn.includes('CN=Enterprise Admins') ||
        dn.includes('CN=Administrators')
      );
    });

    return !isInStandardAdminGroups;
  });

  return {
    type: 'REPLICATION_RIGHTS',
    severity: 'high',
    category: 'advanced',
    title: 'Replication Rights',
    description: 'Account with adminCount=1 outside standard admin groups. May have replication rights (DCSync).',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check for DCSync capable accounts
 */
export function detectDcsyncCapable(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    return (u as any).hasDcsyncRights; // This would be populated by ACL analysis
  });

  return {
    type: 'DCSYNC_CAPABLE',
    severity: 'high',
    category: 'advanced',
    title: 'DCSync Capable',
    description: 'Account with DS-Replication-Get-Changes and DS-Replication-Get-Changes-All rights. Can extract all password hashes.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check for ESC8 HTTP enrollment
 */
export function detectEsc8HttpEnrollment(cas: any[], includeDetails: boolean): Finding {
  const affected = cas.filter((ca) => {
    return ca.webEnrollment && ca.webEnrollment.protocol === 'http';
  });

  return {
    type: 'ESC8_HTTP_ENROLLMENT',
    severity: 'medium',
    category: 'advanced',
    title: 'ESC8 HTTP Enrollment',
    description: 'ADCS web enrollment via HTTP. Enables NTLM relay attacks against certificate enrollment.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((ca) => ca.dn) : undefined,
  };
}

/**
 * Check for LAPS not deployed
 */
export function detectLapsNotDeployed(computers: ADComputer[], includeDetails: boolean): Finding {
  const affected = computers.filter((c) => {
    return !('ms-Mcs-AdmPwd' in c) && !('msLAPS-Password' in c);
  });

  return {
    type: 'LAPS_NOT_DEPLOYED',
    severity: 'medium',
    category: 'advanced',
    title: 'LAPS Not Deployed',
    description: 'LAPS not deployed on domain computers. Shared/static local admin passwords across workstations.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((c) => c.dn) : undefined,
  };
}

/**
 * Check for legacy LAPS attribute
 */
export function detectLapsLegacyAttribute(computers: ADComputer[], includeDetails: boolean): Finding {
  const affected = computers.filter((c) => {
    return 'ms-Mcs-AdmPwd' in c && !('msLAPS-Password' in c);
  });

  return {
    type: 'LAPS_LEGACY_ATTRIBUTE',
    severity: 'medium',
    category: 'advanced',
    title: 'LAPS Legacy Attribute',
    description: 'Legacy LAPS attribute used instead of Windows LAPS. Less secure implementation.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((c) => c.dn) : undefined,
  };
}

/**
 * Check for duplicate SPNs
 */
export function detectDuplicateSpn(users: ADUser[], includeDetails: boolean): Finding {
  const spnMap = new Map<string, string[]>();

  // Build SPN to user DN mapping
  users.forEach((u) => {
    const spns = (u as any).servicePrincipalName;
    if (spns && Array.isArray(spns)) {
      spns.forEach((spn: string) => {
        if (!spnMap.has(spn)) {
          spnMap.set(spn, []);
        }
        spnMap.get(spn)!.push(u.dn);
      });
    }
  });

  // Find duplicate SPNs
  const affected: string[] = [];
  spnMap.forEach((dns, _spn) => {
    if (dns.length > 1) {
      affected.push(...dns);
    }
  });

  return {
    type: 'DUPLICATE_SPN',
    severity: 'medium',
    category: 'advanced',
    title: 'Duplicate SPN',
    description: 'Service Principal Name registered multiple times. Can cause Kerberos authentication failures.',
    count: affected.length,
    affectedEntities: includeDetails ? affected : undefined,
  };
}

/**
 * Check for weak password policy
 */
export function detectWeakPasswordPolicy(domain: ADDomain | null, includeDetails: boolean): Finding {
  if (!domain) {
    return {
      type: 'WEAK_PASSWORD_POLICY',
      severity: 'medium',
      category: 'advanced',
      title: 'Weak Password Policy',
      description: 'Unable to check domain password policy.',
      count: 0,
    };
  }

  const minPwdLength = (domain as any).minPwdLength || 0;
  const maxPwdAge = (domain as any).maxPwdAge || 0;
  const pwdHistoryLength = (domain as any).pwdHistoryLength || 0;

  const isWeak = minPwdLength < 14 || maxPwdAge > 90 || pwdHistoryLength < 24;

  return {
    type: 'WEAK_PASSWORD_POLICY',
    severity: 'medium',
    category: 'advanced',
    title: 'Weak Password Policy',
    description: 'Domain password policy below minimum standards. Enables easier password cracking.',
    count: isWeak ? 1 : 0,
    affectedEntities: includeDetails && isWeak ? [domain.dn] : undefined,
    details: isWeak
      ? {
          minPwdLength,
          maxPwdAge,
          pwdHistoryLength,
        }
      : undefined,
  };
}

/**
 * Check for weak Kerberos policy
 */
export function detectWeakKerberosPolicy(domain: ADDomain | null, includeDetails: boolean): Finding {
  if (!domain) {
    return {
      type: 'WEAK_KERBEROS_POLICY',
      severity: 'medium',
      category: 'advanced',
      title: 'Weak Kerberos Policy',
      description: 'Unable to check Kerberos policy.',
      count: 0,
    };
  }

  const maxTicketAge = (domain as any).maxTicketAge || 0;
  const maxRenewAge = (domain as any).maxRenewAge || 0;

  const isWeak = maxTicketAge > 10 || maxRenewAge > 7;

  return {
    type: 'WEAK_KERBEROS_POLICY',
    severity: 'medium',
    category: 'advanced',
    title: 'Weak Kerberos Policy',
    description: 'Kerberos ticket lifetimes exceed recommended values. Longer window for ticket-based attacks.',
    count: isWeak ? 1 : 0,
    affectedEntities: includeDetails && isWeak ? [domain.dn] : undefined,
    details: isWeak
      ? {
          maxTicketAge,
          maxRenewAge,
        }
      : undefined,
  };
}

/**
 * Check for machine account quota abuse
 */
export function detectMachineAccountQuotaAbuse(domain: ADDomain | null, includeDetails: boolean): Finding {
  if (!domain) {
    return {
      type: 'MACHINE_ACCOUNT_QUOTA_ABUSE',
      severity: 'medium',
      category: 'advanced',
      title: 'Machine Account Quota Abuse',
      description: 'Unable to check machine account quota.',
      count: 0,
    };
  }

  const quota = (domain as any)['ms-DS-MachineAccountQuota'];
  const isVulnerable = typeof quota === 'number' && quota > 0;

  return {
    type: 'MACHINE_ACCOUNT_QUOTA_ABUSE',
    severity: 'medium',
    category: 'advanced',
    title: 'Machine Account Quota Abuse',
    description: 'ms-DS-MachineAccountQuota > 0. Non-admin users can join computers to domain (potential Kerberos attacks).',
    count: isVulnerable ? 1 : 0,
    affectedEntities: includeDetails && isVulnerable ? [domain.dn] : undefined,
    details: isVulnerable
      ? {
          quota,
        }
      : undefined,
  };
}

/**
 * Check for machine account quota set higher than default
 * Default is 10 - values > 10 indicate intentional increase
 */
export function detectMachineAccountQuotaHigh(domain: ADDomain | null, includeDetails: boolean): Finding {
  if (!domain) {
    return {
      type: 'MACHINE_ACCOUNT_QUOTA_HIGH',
      severity: 'high',
      category: 'advanced',
      title: 'Machine Account Quota Elevated',
      description: 'Unable to check machine account quota.',
      count: 0,
    };
  }

  const quota = (domain as any)['ms-DS-MachineAccountQuota'];
  const DEFAULT_QUOTA = 10;
  const isElevated = typeof quota === 'number' && quota > DEFAULT_QUOTA;

  return {
    type: 'MACHINE_ACCOUNT_QUOTA_HIGH',
    severity: 'high',
    category: 'advanced',
    title: 'Machine Account Quota Elevated Above Default',
    description:
      'ms-DS-MachineAccountQuota is higher than the default (10). Someone intentionally increased this value, allowing non-admin users to join more computers to the domain.',
    count: isElevated ? 1 : 0,
    affectedEntities: includeDetails && isElevated ? [domain.dn] : undefined,
    details: isElevated
      ? {
          currentQuota: quota,
          defaultQuota: DEFAULT_QUOTA,
          recommendation: 'Set ms-DS-MachineAccountQuota to 0 to prevent non-admin domain joins.',
        }
      : undefined,
  };
}

/**
 * Check for delegation privilege
 */
export function detectDelegationPrivilege(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    return (u as any).hasSeEnableDelegationPrivilege;
  });

  return {
    type: 'DELEGATION_PRIVILEGE',
    severity: 'medium',
    category: 'advanced',
    title: 'Delegation Privilege',
    description: 'Account has SeEnableDelegationPrivilege. Can enable delegation on user/computer accounts.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

/**
 * Check for foreign security principals
 */
export function detectForeignSecurityPrincipals(fsps: any[], includeDetails: boolean): Finding {
  return {
    type: 'FOREIGN_SECURITY_PRINCIPALS',
    severity: 'medium',
    category: 'advanced',
    title: 'Foreign Security Principals',
    description: 'Foreign security principals from external forests. Potential for cross-forest privilege escalation.',
    count: fsps.length,
    affectedEntities: includeDetails ? fsps.map((fsp) => fsp.dn) : undefined,
  };
}

/**
 * Check for NTLM relay opportunity
 */
export function detectNtlmRelayOpportunity(domain: ADDomain | null, includeDetails: boolean): Finding {
  if (!domain) {
    return {
      type: 'NTLM_RELAY_OPPORTUNITY',
      severity: 'medium',
      category: 'advanced',
      title: 'NTLM Relay Opportunity',
      description: 'Unable to check LDAP signing configuration.',
      count: 0,
    };
  }

  const ldapSigningRequired = (domain as any).ldapSigningRequired;
  const channelBindingRequired = (domain as any).channelBindingRequired;

  const isVulnerable = !ldapSigningRequired || !channelBindingRequired;

  return {
    type: 'NTLM_RELAY_OPPORTUNITY',
    severity: 'medium',
    category: 'advanced',
    title: 'NTLM Relay Opportunity',
    description: 'LDAP signing or channel binding not enforced. Enables NTLM relay attacks.',
    count: isVulnerable ? 1 : 0,
    affectedEntities: includeDetails && isVulnerable ? [domain.dn] : undefined,
  };
}

/**
 * Check for LAPS password set (informational)
 */
export function detectLapsPasswordSet(computers: ADComputer[], includeDetails: boolean): Finding {
  const affected = computers.filter((c) => {
    return 'ms-Mcs-AdmPwd' in c || 'msLAPS-Password' in c;
  });

  return {
    type: 'LAPS_PASSWORD_SET',
    severity: 'low',
    category: 'advanced',
    title: 'LAPS Password Set',
    description: 'LAPS password successfully managed. Informational - indicates proper LAPS deployment.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((c) => c.dn) : undefined,
  };
}

/**
 * Check for LAPS password leaked
 */
export function detectLapsPasswordLeaked(computers: ADComputer[], includeDetails: boolean): Finding {
  const affected = computers.filter((c) => {
    return (c as any).lapsPasswordExcessiveReaders; // This would be populated by ACL analysis
  });

  return {
    type: 'LAPS_PASSWORD_LEAKED',
    severity: 'low',
    category: 'advanced',
    title: 'LAPS Password Leaked',
    description: 'LAPS password visible to too many users. Reduces effectiveness of LAPS.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((c) => c.dn) : undefined,
  };
}

/**
 * Check for ADCS weak permissions
 */
export function detectAdcsWeakPermissions(templates: any[], includeDetails: boolean): Finding {
  const affected = templates.filter((t) => {
    // Check if template has weak ACLs allowing enrollment by non-admins
    return t.hasWeakEnrollmentAcl || t.hasGenericAllPermission;
  });

  return {
    type: 'ADCS_WEAK_PERMISSIONS',
    severity: 'medium',
    category: 'advanced',
    title: 'ADCS Weak Permissions',
    description: 'Weak permissions on ADCS objects or certificate templates allow unauthorized enrollment.',
    count: affected.length,
    affectedEntities: includeDetails ? affected.map((t) => t.dn || t.name) : undefined,
  };
}

/**
 * Check for dangerous logon scripts with weak ACLs
 */
export function detectDangerousLogonScripts(users: ADUser[], includeDetails: boolean): Finding {
  const affected = users.filter((u) => {
    const scriptPath = (u as any).scriptPath;
    // Check if user has logon script configured
    // In real implementation, would check ACLs on script file/share
    return scriptPath && (scriptPath.includes('\\\\') || scriptPath.startsWith('//'));
  });

  return {
    type: 'DANGEROUS_LOGON_SCRIPTS',
    severity: 'medium',
    category: 'advanced',
    title: 'Dangerous Logon Scripts',
    description: 'Logon scripts with weak ACLs can be modified by attackers for code execution on user login.',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
  };
}

// ==================== PHASE 1B DETECTORS ====================

/**
 * Check if anonymous LDAP access is allowed
 * This is tested during the audit via separate anonymous bind attempt
 */
export function detectAnonymousLdapAccess(
  anonymousAccessAllowed: boolean,
  domain: ADDomain | null,
  includeDetails: boolean
): Finding {
  return {
    type: 'ANONYMOUS_LDAP_ACCESS',
    severity: 'medium',
    category: 'advanced',
    title: 'Anonymous LDAP Access Allowed',
    description:
      'LDAP server accepts anonymous binds. Attackers can enumerate AD objects (users, groups, computers) without valid credentials.',
    count: anonymousAccessAllowed ? 1 : 0,
    affectedEntities: includeDetails && anonymousAccessAllowed && domain ? [domain.dn] : undefined,
    details: anonymousAccessAllowed
      ? {
          recommendation:
            'Configure "Network security: LDAP client signing requirements" and restrict anonymous access via dsHeuristics.',
          currentStatus: 'Anonymous bind allowed',
        }
      : undefined,
  };
}

/**
 * Check if AD Recycle Bin is disabled
 * Recycle Bin allows recovery of deleted objects
 */
export function detectRecycleBinDisabled(domain: ADDomain | null, includeDetails: boolean): Finding {
  if (!domain) {
    return {
      type: 'RECYCLE_BIN_DISABLED',
      severity: 'medium',
      category: 'advanced',
      title: 'AD Recycle Bin Status Unknown',
      description: 'Unable to determine AD Recycle Bin status.',
      count: 0,
    };
  }

  const recycleBinEnabled = (domain as any).recycleBinEnabled === true;

  return {
    type: 'RECYCLE_BIN_DISABLED',
    severity: 'medium',
    category: 'advanced',
    title: 'AD Recycle Bin Not Enabled',
    description:
      'Active Directory Recycle Bin is not enabled. Deleted objects cannot be easily recovered, which complicates incident response and may lead to permanent data loss.',
    count: recycleBinEnabled ? 0 : 1,
    affectedEntities: includeDetails && !recycleBinEnabled ? [domain.dn] : undefined,
    details: !recycleBinEnabled
      ? {
          recommendation:
            'Enable AD Recycle Bin feature. Note: This requires forest functional level 2008 R2 or higher and is irreversible.',
          currentStatus: 'Disabled',
        }
      : undefined,
  };
}

/**
 * GPO Security Settings from SYSVOL
 */
export interface GpoSecuritySettings {
  /** LDAP server signing requirement: 0=none, 1=negotiate, 2=require */
  ldapServerIntegrity?: number;
  /** LDAP channel binding: 0=never, 1=when supported, 2=always */
  ldapChannelBinding?: number;
  /** SMBv1 server enabled */
  smbv1ServerEnabled?: boolean;
  /** SMBv1 client enabled */
  smbv1ClientEnabled?: boolean;
  /** SMB Server signing required (RequireSecuritySignature) */
  smbSigningRequired?: boolean;
  /** SMB Client signing required */
  smbClientSigningRequired?: boolean;
  /** Audit policies configured */
  auditPolicies?: {
    category: string;
    subcategory?: string;
    success: boolean;
    failure: boolean;
  }[];
  /** PowerShell logging settings */
  powershellLogging?: {
    moduleLogging: boolean;
    scriptBlockLogging: boolean;
    transcription: boolean;
  };
}

/**
 * Check if LDAP signing is disabled
 * Requires GPO settings from SYSVOL
 */
export function detectLdapSigningDisabled(
  gpoSettings: GpoSecuritySettings | null,
  domain: ADDomain | null,
  includeDetails: boolean
): Finding {
  // If we have GPO settings, use them
  if (gpoSettings && gpoSettings.ldapServerIntegrity !== undefined) {
    const signingDisabled = gpoSettings.ldapServerIntegrity === 0;

    return {
      type: 'LDAP_SIGNING_DISABLED',
      severity: 'critical',
      category: 'advanced',
      title: 'LDAP Signing Not Required',
      description:
        'LDAP server signing is not required. This allows NTLM relay attacks and man-in-the-middle attacks against LDAP connections.',
      count: signingDisabled ? 1 : 0,
      affectedEntities: includeDetails && signingDisabled && domain ? [domain.dn] : undefined,
      details: signingDisabled
        ? {
            recommendation: 'Configure "Domain controller: LDAP server signing requirements" to "Require signing".',
            currentSetting: gpoSettings.ldapServerIntegrity,
            requiredSetting: 2,
          }
        : undefined,
    };
  }

  // If GPO settings not available, assume vulnerable (Windows defaults don't require LDAP signing)
  return {
    type: 'LDAP_SIGNING_DISABLED',
    severity: 'critical',
    category: 'advanced',
    title: 'LDAP Signing Not Configured in GPO',
    description:
      'LDAP signing is not configured via Group Policy. Windows defaults do not require LDAP signing, making this environment vulnerable to LDAP relay attacks.',
    count: 1,
    affectedEntities: includeDetails && domain ? [domain.dn] : undefined,
    details: {
      recommendation:
        'Configure "Domain controller: LDAP server signing requirements" to "Require signing" via Group Policy.',
      note: 'No GPO security template found. Windows defaults do not require LDAP signing.',
    },
  };
}

/**
 * Check if LDAP channel binding is disabled
 * Requires GPO settings from SYSVOL
 */
export function detectLdapChannelBindingDisabled(
  gpoSettings: GpoSecuritySettings | null,
  domain: ADDomain | null,
  includeDetails: boolean
): Finding {
  if (gpoSettings && gpoSettings.ldapChannelBinding !== undefined) {
    const bindingDisabled = gpoSettings.ldapChannelBinding === 0;

    return {
      type: 'LDAP_CHANNEL_BINDING_DISABLED',
      severity: 'high',
      category: 'advanced',
      title: 'LDAP Channel Binding Not Required',
      description:
        'LDAP channel binding is not required. This allows NTLM relay attacks against LDAPS connections even when signing is enabled.',
      count: bindingDisabled ? 1 : 0,
      affectedEntities: includeDetails && bindingDisabled && domain ? [domain.dn] : undefined,
      details: bindingDisabled
        ? {
            recommendation: 'Configure "Domain controller: LDAP server channel binding token requirements" to "Always".',
            currentSetting: gpoSettings.ldapChannelBinding,
            requiredSetting: 2,
          }
        : undefined,
    };
  }

  return {
    type: 'LDAP_CHANNEL_BINDING_DISABLED',
    severity: 'high',
    category: 'advanced',
    title: 'LDAP Channel Binding Configuration Unknown',
    description: 'Unable to determine LDAP channel binding configuration. Manual review recommended.',
    count: 0,
    details: {
      note: 'GPO/Registry settings not available. Check LdapEnforceChannelBinding registry value manually.',
    },
  };
}

/**
 * Check if SMBv1 is enabled
 * Requires GPO settings from SYSVOL
 */
export function detectSmbV1Enabled(
  gpoSettings: GpoSecuritySettings | null,
  domain: ADDomain | null,
  includeDetails: boolean
): Finding {
  if (gpoSettings && (gpoSettings.smbv1ServerEnabled !== undefined || gpoSettings.smbv1ClientEnabled !== undefined)) {
    const smbv1Enabled = gpoSettings.smbv1ServerEnabled === true || gpoSettings.smbv1ClientEnabled === true;

    return {
      type: 'SMB_V1_ENABLED',
      severity: 'high',
      category: 'advanced',
      title: 'SMBv1 Protocol Enabled',
      description:
        'SMBv1 protocol is enabled. SMBv1 is deprecated and vulnerable to attacks like EternalBlue (WannaCry, NotPetya).',
      count: smbv1Enabled ? 1 : 0,
      affectedEntities: includeDetails && smbv1Enabled && domain ? [domain.dn] : undefined,
      details: smbv1Enabled
        ? {
            recommendation: 'Disable SMBv1 on all systems. Use SMBv2/v3 instead.',
            smbv1Server: gpoSettings.smbv1ServerEnabled,
            smbv1Client: gpoSettings.smbv1ClientEnabled,
          }
        : undefined,
    };
  }

  return {
    type: 'SMB_V1_ENABLED',
    severity: 'high',
    category: 'advanced',
    title: 'SMBv1 Configuration Unknown',
    description: 'Unable to determine SMBv1 configuration. Manual review recommended.',
    count: 0,
    details: {
      note: 'GPO/Registry settings not available. Check SMB1 registry values and Windows features manually.',
    },
  };
}

/**
 * Check if SMB signing is disabled
 * Requires GPO settings from SYSVOL
 *
 * SMB signing prevents man-in-the-middle attacks and NTLM relay attacks.
 * Registry key: MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature
 */
export function detectSmbSigningDisabled(
  gpoSettings: GpoSecuritySettings | null,
  domain: ADDomain | null,
  includeDetails: boolean
): Finding {
  if (gpoSettings && gpoSettings.smbSigningRequired !== undefined) {
    const signingDisabled = gpoSettings.smbSigningRequired === false;

    return {
      type: 'SMB_SIGNING_DISABLED',
      severity: 'critical',
      category: 'advanced',
      title: 'SMB Signing Not Required',
      description:
        'SMB server signing is not required. This allows man-in-the-middle attacks and NTLM relay attacks against SMB connections.',
      count: signingDisabled ? 1 : 0,
      affectedEntities: includeDetails && signingDisabled && domain ? [domain.dn] : undefined,
      details: signingDisabled
        ? {
            recommendation: 'Configure "Microsoft network server: Digitally sign communications (always)" to Enabled.',
            currentSetting: 'Not Required',
            requiredSetting: 'Required',
            smbServerSigning: gpoSettings.smbSigningRequired,
            smbClientSigning: gpoSettings.smbClientSigningRequired,
          }
        : undefined,
    };
  }

  // If GPO settings not available, assume vulnerable (Windows defaults don't require signing)
  return {
    type: 'SMB_SIGNING_DISABLED',
    severity: 'critical',
    category: 'advanced',
    title: 'SMB Signing Not Configured in GPO',
    description:
      'SMB signing is not configured via Group Policy. Windows defaults do not require SMB signing, making this environment vulnerable to NTLM relay attacks.',
    count: 1,
    affectedEntities: includeDetails && domain ? [domain.dn] : undefined,
    details: {
      recommendation:
        'Configure "Microsoft network server: Digitally sign communications (always)" via Group Policy.',
      note: 'No GPO security template found. Windows defaults do not require SMB signing.',
    },
  };
}

/**
 * Check if audit policy is weak/incomplete
 * Requires GPO settings from SYSVOL
 */
export function detectAuditPolicyWeak(
  gpoSettings: GpoSecuritySettings | null,
  domain: ADDomain | null,
  includeDetails: boolean
): Finding {
  // Critical audit categories that should be enabled
  const criticalAuditCategories = [
    'Account Logon',
    'Account Management',
    'Logon/Logoff',
    'Object Access',
    'Policy Change',
    'Privilege Use',
    'System',
  ];

  if (gpoSettings && gpoSettings.auditPolicies && gpoSettings.auditPolicies.length > 0) {
    const configuredCategories = new Set(gpoSettings.auditPolicies.map((p) => p.category));
    const missingCategories = criticalAuditCategories.filter((cat) => !configuredCategories.has(cat));

    // Check if critical events are being audited
    const hasWeakAudit = missingCategories.length > 0;

    return {
      type: 'AUDIT_POLICY_WEAK',
      severity: 'medium',
      category: 'advanced',
      title: 'Audit Policy Incomplete',
      description:
        'Domain audit policy does not cover all critical security events. Attacks may go undetected.',
      count: hasWeakAudit ? 1 : 0,
      affectedEntities: includeDetails && hasWeakAudit && domain ? [domain.dn] : undefined,
      details: hasWeakAudit
        ? {
            recommendation: 'Configure Advanced Audit Policy to audit all critical security categories.',
            missingCategories,
            configuredCategories: Array.from(configuredCategories),
          }
        : undefined,
    };
  }

  return {
    type: 'AUDIT_POLICY_WEAK',
    severity: 'medium',
    category: 'advanced',
    title: 'Audit Policy Configuration Unknown',
    description: 'Unable to determine audit policy configuration. Manual review recommended.',
    count: 0,
    details: {
      note: 'GPO audit settings not available. Check Advanced Audit Policy Configuration manually.',
      requiredCategories: criticalAuditCategories,
    },
  };
}

/**
 * Check if PowerShell logging is disabled
 * Requires GPO settings from SYSVOL
 */
export function detectPowershellLoggingDisabled(
  gpoSettings: GpoSecuritySettings | null,
  domain: ADDomain | null,
  includeDetails: boolean
): Finding {
  if (gpoSettings && gpoSettings.powershellLogging) {
    const logging = gpoSettings.powershellLogging;
    const loggingDisabled = !logging.moduleLogging && !logging.scriptBlockLogging;

    return {
      type: 'POWERSHELL_LOGGING_DISABLED',
      severity: 'medium',
      category: 'advanced',
      title: 'PowerShell Logging Not Configured',
      description:
        'PowerShell script block logging and module logging are not enabled. Malicious PowerShell activity will not be logged.',
      count: loggingDisabled ? 1 : 0,
      affectedEntities: includeDetails && loggingDisabled && domain ? [domain.dn] : undefined,
      details: loggingDisabled
        ? {
            recommendation:
              'Enable "Turn on PowerShell Script Block Logging" and "Turn on Module Logging" via GPO.',
            moduleLogging: logging.moduleLogging,
            scriptBlockLogging: logging.scriptBlockLogging,
            transcription: logging.transcription,
          }
        : undefined,
    };
  }

  return {
    type: 'POWERSHELL_LOGGING_DISABLED',
    severity: 'medium',
    category: 'advanced',
    title: 'PowerShell Logging Configuration Unknown',
    description: 'Unable to determine PowerShell logging configuration. Manual review recommended.',
    count: 0,
    details: {
      note: 'GPO/Registry settings not available. Check PowerShell logging GPO settings manually.',
    },
  };
}

/**
 * Advanced detector options
 */
/**
 * Detect modified dsHeuristics attribute
 *
 * dsHeuristics controls various AD behaviors. Non-default values may indicate
 * security weakening (e.g., allowing anonymous access, disabling list object mode).
 *
 * @param domain - Domain information
 * @param _includeDetails - Whether to include affected entity details
 * @returns Finding for DS_HEURISTICS_MODIFIED
 */
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

/**
 * Detect modified AdminSDHolder permissions
 *
 * AdminSDHolder template is applied to protected accounts every 60 minutes.
 * Modified permissions on AdminSDHolder will propagate to all protected accounts.
 *
 * @param domain - Domain information
 * @param _includeDetails - Whether to include affected entity details
 * @returns Finding for ADMIN_SD_HOLDER_MODIFIED
 */
export function detectAdminSdHolderModified(
  domain: ADDomain | null,
  _includeDetails: boolean
): Finding {
  // This would require reading the nTSecurityDescriptor of AdminSDHolder
  // For now, check if domain has indicators of modification
  // A proper check would compare against known-good template
  const adminSdHolderInfo = domain
    ? (domain as Record<string, unknown>)['adminSDHolderModified'] as boolean | undefined
    : undefined;

  return {
    type: 'ADMIN_SD_HOLDER_MODIFIED',
    severity: 'high',
    category: 'advanced',
    title: 'AdminSDHolder Review Required',
    description:
      'AdminSDHolder permissions should be reviewed. Modifications propagate to all protected accounts ' +
      '(Domain Admins, Enterprise Admins, etc.) via SDProp process.',
    count: adminSdHolderInfo ? 1 : 0,
    details: {
      recommendation:
        'Compare AdminSDHolder ACL against baseline. Look for non-standard principals with permissions.',
      checkCommand: 'Get-ADObject "CN=AdminSDHolder,CN=System,DC=..." -Properties nTSecurityDescriptor',
    },
  };
}

/**
 * Detect Exchange privilege escalation paths
 *
 * Exchange security groups often have dangerous permissions that can be
 * abused for privilege escalation (WriteDacl on domain, etc.).
 *
 * @param users - Array of AD users
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for EXCHANGE_PRIV_ESC_PATH
 */
export function detectExchangePrivEscPath(
  users: ADUser[],
  includeDetails: boolean
): Finding {
  // Exchange groups with dangerous permissions
  const exchangeGroups = [
    'Exchange Trusted Subsystem',
    'Exchange Windows Permissions',
    'Organization Management',
    'Exchange Servers',
  ];

  // Find users in Exchange groups that might indicate privilege escalation risk
  const affected = users.filter((u) => {
    if (!u.enabled || !u.memberOf) return false;
    return u.memberOf.some((dn) =>
      exchangeGroups.some((eg) => dn.toLowerCase().includes(eg.toLowerCase()))
    );
  });

  return {
    type: 'EXCHANGE_PRIV_ESC_PATH',
    severity: 'critical',
    category: 'advanced',
    title: 'Exchange Privilege Escalation Risk',
    description:
      'Users in Exchange security groups with potentially dangerous permissions. ' +
      'Exchange Trusted Subsystem has WriteDacl on domain by default (CVE-2019-1166).',
    count: affected.length,
    affectedEntities: includeDetails ? toAffectedUserEntities(affected) : undefined,
    details: {
      exchangeGroups: exchangeGroups,
      recommendation:
        'Review Exchange group permissions on domain head. Apply PrivExchange mitigations.',
      reference: 'CVE-2019-1166, PrivExchange',
    },
  };
}

export interface AdvancedDetectorOptions {
  /** GPO security settings from SYSVOL */
  gpoSettings?: GpoSecuritySettings | null;
  /** Whether anonymous LDAP access is allowed */
  anonymousAccessAllowed?: boolean;
}

/**
 * Detect all advanced vulnerabilities
 */
export function detectAdvancedVulnerabilities(
  users: ADUser[],
  computers: ADComputer[],
  domain: ADDomain | null,
  templates: any[] = [],
  cas: any[] = [],
  fsps: any[] = [],
  includeDetails: boolean,
  options: AdvancedDetectorOptions = {}
): Finding[] {
  const { gpoSettings = null, anonymousAccessAllowed = false } = options;

  return [
    // Critical
    detectShadowCredentials(users, includeDetails),
    detectRbcdAbuse(users, includeDetails),
    // Critical (GPO-based) - Story 1.1
    detectLdapSigningDisabled(gpoSettings, domain, includeDetails),
    detectSmbSigningDisabled(gpoSettings, domain, includeDetails),
    // High
    detectEsc1VulnerableTemplate(templates, includeDetails),
    detectEsc2AnyPurpose(templates, includeDetails),
    detectEsc3EnrollmentAgent(templates, includeDetails),
    detectEsc4VulnerableTemplateAcl(templates, includeDetails),
    detectEsc6EditfAttributeSubjectAltName2(cas, includeDetails),
    detectLapsPasswordReadable(computers, includeDetails),
    detectReplicationRights(users, includeDetails),
    detectDcsyncCapable(users, includeDetails),
    // High (domain)
    detectMachineAccountQuotaHigh(domain, includeDetails),
    // High (GPO-based)
    detectLdapChannelBindingDisabled(gpoSettings, domain, includeDetails),
    detectSmbV1Enabled(gpoSettings, domain, includeDetails),
    // Medium
    detectEsc8HttpEnrollment(cas, includeDetails),
    detectLapsNotDeployed(computers, includeDetails),
    detectLapsLegacyAttribute(computers, includeDetails),
    detectDuplicateSpn(users, includeDetails),
    detectWeakPasswordPolicy(domain, includeDetails),
    detectWeakKerberosPolicy(domain, includeDetails),
    detectMachineAccountQuotaAbuse(domain, includeDetails),
    detectDelegationPrivilege(users, includeDetails),
    detectForeignSecurityPrincipals(fsps, includeDetails),
    detectNtlmRelayOpportunity(domain, includeDetails),
    detectAdcsWeakPermissions(templates, includeDetails),
    detectDangerousLogonScripts(users, includeDetails),
    // Medium (Phase 1B)
    detectRecycleBinDisabled(domain, includeDetails),
    detectAnonymousLdapAccess(anonymousAccessAllowed, domain, includeDetails),
    detectAuditPolicyWeak(gpoSettings, domain, includeDetails),
    detectPowershellLoggingDisabled(gpoSettings, domain, includeDetails),
    // Low
    detectLapsPasswordSet(computers, includeDetails),
    detectLapsPasswordLeaked(computers, includeDetails),
    // Phase 4: Advanced detections
    detectDsHeuristicsModified(domain, includeDetails),
    detectAdminSdHolderModified(domain, includeDetails),
    detectExchangePrivEscPath(users, includeDetails),
  ].filter(
    (finding) =>
      finding.count > 0 ||
      // Always include critical signing findings (even with count=0) for visibility
      finding.type === 'SMB_SIGNING_DISABLED' ||
      finding.type === 'LDAP_SIGNING_DISABLED'
  );
}
