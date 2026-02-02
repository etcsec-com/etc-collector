/**
 * Permissions & ACL Security Vulnerability Detector
 *
 * Detects ACL-related vulnerabilities in AD.
 * Story 1.7: AD Vulnerability Detection Engine
 *
 * Vulnerabilities detected (15):
 * CRITICAL (1) - Phase 4:
 * - ACL_DS_REPLICATION_GET_CHANGES
 *
 * HIGH (4):
 * - ACL_GENERICALL
 * - ACL_WRITEDACL
 * - ACL_WRITEOWNER
 * - ACL_SELF_MEMBERSHIP - Phase 4
 *
 * MEDIUM (10):
 * - ACL_GENERICWRITE
 * - ACL_FORCECHANGEPASSWORD
 * - EVERYONE_IN_ACL
 * - WRITESPN_ABUSE
 * - GPO_LINK_POISONING
 * - ADMINSDHOLDER_BACKDOOR
 * - ACL_ADD_MEMBER - Phase 4
 * - ACL_WRITE_PROPERTY_EXTENDED - Phase 4
 * - ACL_USER_FORCE_CHANGE_PASSWORD - Phase 4
 * - ACL_COMPUTER_WRITE_VALIDATED_DNS - Phase 4
 */

import { Finding } from '../../../../types/finding.types';
import { AclEntry } from '../../../../types/ad.types';

/**
 * Helper to get unique objects from ACL entries
 */
function getUniqueObjects(entries: AclEntry[]): string[] {
  return [...new Set(entries.map((ace) => ace.objectDn))];
}

/**
 * Check for GenericAll permission on sensitive objects
 *
 * GENERIC_ALL can be stored as:
 * - 0x10000000 (raw GENERIC_ALL)
 * - 0x000F01FF (Full Control for AD objects - mapped rights)
 */
export function detectAclGenericAll(aclEntries: AclEntry[], includeDetails: boolean): Finding {
  // GENERIC_ALL raw value
  const GENERIC_ALL = 0x10000000;
  // Full control mask for AD objects (all specific AD rights + standard rights)
  // This is what GENERIC_ALL maps to when stored in AD ACLs
  const AD_FULL_CONTROL = 0x000f01ff;

  const affected = aclEntries.filter((ace) => {
    // Check for raw GENERIC_ALL
    if ((ace.accessMask & GENERIC_ALL) !== 0) return true;
    // Check for Full Control (GENERIC_ALL mapped to AD rights)
    // The mask 0x000F01FF includes: DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | all DS rights
    return (ace.accessMask & AD_FULL_CONTROL) === AD_FULL_CONTROL;
  });

  const uniqueObjects = getUniqueObjects(affected);
  const totalInstances = affected.length;

  return {
    type: 'ACL_GENERICALL',
    severity: 'high',
    category: 'permissions',
    title: 'ACL GenericAll',
    description: 'GenericAll permission on sensitive AD objects. Full control over object (reset passwords, modify groups, etc.).',
    count: uniqueObjects.length,
    totalInstances: totalInstances !== uniqueObjects.length ? totalInstances : undefined,
    affectedEntities: includeDetails ? uniqueObjects : undefined,
  };
}

/**
 * Check for WriteDACL permission on sensitive objects
 */
export function detectAclWriteDacl(aclEntries: AclEntry[], includeDetails: boolean): Finding {
  const WRITE_DACL = 0x00040000;

  const affected = aclEntries.filter((ace) => {
    return (ace.accessMask & WRITE_DACL) !== 0;
  });

  const uniqueObjects = getUniqueObjects(affected);
  const totalInstances = affected.length;

  return {
    type: 'ACL_WRITEDACL',
    severity: 'high',
    category: 'permissions',
    title: 'ACL WriteDACL',
    description: "WriteDACL permission on sensitive AD objects. Can modify object's security descriptor to grant additional permissions.",
    count: uniqueObjects.length,
    totalInstances: totalInstances !== uniqueObjects.length ? totalInstances : undefined,
    affectedEntities: includeDetails ? uniqueObjects : undefined,
  };
}

/**
 * Check for WriteOwner permission on sensitive objects
 */
export function detectAclWriteOwner(aclEntries: AclEntry[], includeDetails: boolean): Finding {
  const WRITE_OWNER = 0x00080000;

  const affected = aclEntries.filter((ace) => {
    return (ace.accessMask & WRITE_OWNER) !== 0;
  });

  const uniqueObjects = getUniqueObjects(affected);
  const totalInstances = affected.length;

  return {
    type: 'ACL_WRITEOWNER',
    severity: 'high',
    category: 'permissions',
    title: 'ACL WriteOwner',
    description: 'WriteOwner permission on sensitive AD objects. Can take ownership of object and modify permissions.',
    count: uniqueObjects.length,
    totalInstances: totalInstances !== uniqueObjects.length ? totalInstances : undefined,
    affectedEntities: includeDetails ? uniqueObjects : undefined,
  };
}

/**
 * Check for GenericWrite permission on sensitive objects
 */
export function detectAclGenericWrite(aclEntries: AclEntry[], includeDetails: boolean): Finding {
  const GENERIC_WRITE = 0x40000000;

  const affected = aclEntries.filter((ace) => {
    return (ace.accessMask & GENERIC_WRITE) !== 0;
  });

  const uniqueObjects = getUniqueObjects(affected);
  const totalInstances = affected.length;

  return {
    type: 'ACL_GENERICWRITE',
    severity: 'medium',
    category: 'permissions',
    title: 'ACL GenericWrite',
    description: 'GenericWrite permission on sensitive AD objects. Can modify many object attributes.',
    count: uniqueObjects.length,
    totalInstances: totalInstances !== uniqueObjects.length ? totalInstances : undefined,
    affectedEntities: includeDetails ? uniqueObjects : undefined,
  };
}

/**
 * Check for ForceChangePassword extended right
 */
export function detectAclForceChangePassword(aclEntries: AclEntry[], includeDetails: boolean): Finding {
  const FORCE_CHANGE_PASSWORD_GUID = '00299570-246d-11d0-a768-00aa006e0529';

  const affected = aclEntries.filter((ace) => {
    return ace.objectType === FORCE_CHANGE_PASSWORD_GUID;
  });

  const uniqueObjects = getUniqueObjects(affected);
  const totalInstances = affected.length;

  return {
    type: 'ACL_FORCECHANGEPASSWORD',
    severity: 'medium',
    category: 'permissions',
    title: 'ACL Force Change Password',
    description: 'ExtendedRight to force password change on user accounts. Can reset passwords without knowing current password.',
    count: uniqueObjects.length,
    totalInstances: totalInstances !== uniqueObjects.length ? totalInstances : undefined,
    affectedEntities: includeDetails ? uniqueObjects : undefined,
  };
}

/**
 * Check for Everyone/Authenticated Users with write permissions
 */
export function detectEveryoneInAcl(aclEntries: AclEntry[], includeDetails: boolean): Finding {
  const EVERYONE_SID = 'S-1-1-0';
  const AUTHENTICATED_USERS_SID = 'S-1-5-11';
  const WRITE_MASK = 0x00020000; // ADS_RIGHT_DS_WRITE_PROP

  const affected = aclEntries.filter((ace) => {
    const isEveryone = ace.trustee === EVERYONE_SID || ace.trustee === AUTHENTICATED_USERS_SID;
    const hasWrite = (ace.accessMask & WRITE_MASK) !== 0;
    return isEveryone && hasWrite;
  });

  const uniqueObjects = getUniqueObjects(affected);
  const totalInstances = affected.length;

  return {
    type: 'EVERYONE_IN_ACL',
    severity: 'medium',
    category: 'permissions',
    title: 'Everyone in ACL',
    description: 'Everyone or Authenticated Users with write permissions in ACL. Overly permissive access.',
    count: uniqueObjects.length,
    totalInstances: totalInstances !== uniqueObjects.length ? totalInstances : undefined,
    affectedEntities: includeDetails ? uniqueObjects : undefined,
  };
}

/**
 * Check for WriteProperty permission for servicePrincipalName
 */
export function detectWriteSpnAbuse(aclEntries: AclEntry[], includeDetails: boolean): Finding {
  const SPN_PROPERTY_GUID = 'f3a64788-5306-11d1-a9c5-0000f80367c1';

  const affected = aclEntries.filter((ace) => {
    return ace.objectType === SPN_PROPERTY_GUID;
  });

  const uniqueObjects = getUniqueObjects(affected);
  const totalInstances = affected.length;

  return {
    type: 'WRITESPN_ABUSE',
    severity: 'medium',
    category: 'permissions',
    title: 'Write SPN Abuse',
    description: 'WriteProperty permission for servicePrincipalName attribute. Can set SPNs for targeted Kerberoasting.',
    count: uniqueObjects.length,
    totalInstances: totalInstances !== uniqueObjects.length ? totalInstances : undefined,
    affectedEntities: includeDetails ? uniqueObjects : undefined,
  };
}

/**
 * Check for weak ACLs on Group Policy Objects
 */
export function detectGpoLinkPoisoning(aclEntries: AclEntry[], includeDetails: boolean): Finding {
  const GENERIC_WRITE = 0x40000000;
  const GENERIC_ALL = 0x10000000;
  const WRITE_DACL = 0x00040000;

  const affected = aclEntries.filter((ace) => {
    const isGpo = ace.objectDn.includes('CN=Policies,CN=System');
    const hasDangerousPermission =
      (ace.accessMask & GENERIC_ALL) !== 0 ||
      (ace.accessMask & GENERIC_WRITE) !== 0 ||
      (ace.accessMask & WRITE_DACL) !== 0;

    return isGpo && hasDangerousPermission;
  });

  const uniqueObjects = getUniqueObjects(affected);
  const totalInstances = affected.length;

  return {
    type: 'GPO_LINK_POISONING',
    severity: 'medium',
    category: 'permissions',
    title: 'GPO Link Poisoning',
    description: 'Weak ACLs on Group Policy Objects. Can modify GPO to execute code on targeted systems.',
    count: uniqueObjects.length,
    totalInstances: totalInstances !== uniqueObjects.length ? totalInstances : undefined,
    affectedEntities: includeDetails ? uniqueObjects : undefined,
  };
}

/**
 * Check for unexpected ACL on AdminSDHolder object
 */
export function detectAdminSdHolderBackdoor(aclEntries: AclEntry[], includeDetails: boolean): Finding {
  const affected = aclEntries.filter((ace) => {
    return ace.objectDn.includes('CN=AdminSDHolder,CN=System');
  });

  const uniqueObjects = getUniqueObjects(affected);
  const totalInstances = affected.length;

  return {
    type: 'ADMINSDHOLDER_BACKDOOR',
    severity: 'medium',
    category: 'permissions',
    title: 'AdminSDHolder Backdoor',
    description: 'Unexpected ACL on AdminSDHolder object. Persistent permissions on admin accounts.',
    count: uniqueObjects.length,
    totalInstances: totalInstances !== uniqueObjects.length ? totalInstances : undefined,
    affectedEntities: includeDetails ? uniqueObjects : undefined,
  };
}

/**
 * Detect Self-membership rights on groups
 *
 * Self-membership allows adding oneself to a group, enabling privilege escalation.
 *
 * @param aclEntries - Array of ACL entries
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for ACL_SELF_MEMBERSHIP
 */
export function detectAclSelfMembership(aclEntries: AclEntry[], includeDetails: boolean): Finding {
  // Self-membership GUID: bf9679c0-0de6-11d0-a285-00aa003049e2
  const SELF_MEMBERSHIP_GUID = 'bf9679c0-0de6-11d0-a285-00aa003049e2';
  const WRITE_SELF = 0x8; // ADS_RIGHT_DS_SELF

  const affected = aclEntries.filter((ace) => {
    const hasWriteSelf = (ace.accessMask & WRITE_SELF) !== 0;
    const isSelfMembership =
      ace.objectType?.toLowerCase() === SELF_MEMBERSHIP_GUID ||
      ace.objectType?.toLowerCase().includes('member');
    return hasWriteSelf || isSelfMembership;
  });

  const uniqueObjects = getUniqueObjects(affected);
  const totalInstances = affected.length;

  return {
    type: 'ACL_SELF_MEMBERSHIP',
    severity: 'high',
    category: 'permissions',
    title: 'Self-Membership Rights',
    description:
      'Principals with self-membership rights on groups. ' +
      'Allows adding oneself to a group, potentially gaining elevated privileges.',
    count: uniqueObjects.length,
    totalInstances: totalInstances !== uniqueObjects.length ? totalInstances : undefined,
    affectedEntities: includeDetails ? uniqueObjects : undefined,
  };
}

/**
 * Detect Add-Member rights on groups
 *
 * Add-Member allows adding arbitrary users to groups.
 *
 * @param aclEntries - Array of ACL entries
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for ACL_ADD_MEMBER
 */
export function detectAclAddMember(aclEntries: AclEntry[], includeDetails: boolean): Finding {
  // Member attribute GUID: bf9679c0-0de6-11d0-a285-00aa003049e2
  const MEMBER_GUID = 'bf9679c0-0de6-11d0-a285-00aa003049e2';
  const WRITE_PROPERTY = 0x20;

  const affected = aclEntries.filter((ace) => {
    const hasWriteProperty = (ace.accessMask & WRITE_PROPERTY) !== 0;
    const isMemberProperty = ace.objectType?.toLowerCase() === MEMBER_GUID;
    return hasWriteProperty && isMemberProperty;
  });

  const uniqueObjects = getUniqueObjects(affected);
  const totalInstances = affected.length;

  return {
    type: 'ACL_ADD_MEMBER',
    severity: 'medium',
    category: 'permissions',
    title: 'Add-Member Rights on Groups',
    description:
      'Principals with rights to add members to groups. ' +
      'Can be abused to add accounts to privileged groups.',
    count: uniqueObjects.length,
    totalInstances: totalInstances !== uniqueObjects.length ? totalInstances : undefined,
    affectedEntities: includeDetails ? uniqueObjects : undefined,
  };
}

/**
 * Detect extended write property rights
 *
 * Extended write property rights can be abused for various attacks.
 *
 * @param aclEntries - Array of ACL entries
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for ACL_WRITE_PROPERTY_EXTENDED
 */
export function detectAclWritePropertyExtended(
  aclEntries: AclEntry[],
  includeDetails: boolean
): Finding {
  // Common dangerous extended properties
  const DANGEROUS_PROPERTIES = [
    '00299570-246d-11d0-a768-00aa006e0529', // User-Force-Change-Password
    'bf967a68-0de6-11d0-a285-00aa003049e2', // Script-Path
    'bf967950-0de6-11d0-a285-00aa003049e2', // Home-Directory
    '5f202010-79a5-11d0-9020-00c04fc2d4cf', // ms-DS-Key-Credential-Link (Shadow Credentials)
  ];

  const WRITE_PROPERTY = 0x20;

  const affected = aclEntries.filter((ace) => {
    const hasWriteProperty = (ace.accessMask & WRITE_PROPERTY) !== 0;
    const isDangerousProperty =
      ace.objectType && DANGEROUS_PROPERTIES.includes(ace.objectType.toLowerCase());
    return hasWriteProperty && isDangerousProperty;
  });

  const uniqueObjects = getUniqueObjects(affected);
  const totalInstances = affected.length;

  return {
    type: 'ACL_WRITE_PROPERTY_EXTENDED',
    severity: 'medium',
    category: 'permissions',
    title: 'Extended Write Property Rights',
    description:
      'Principals with dangerous extended write property rights. ' +
      'Can modify script paths, home directories, or key credentials.',
    count: uniqueObjects.length,
    totalInstances: totalInstances !== uniqueObjects.length ? totalInstances : undefined,
    affectedEntities: includeDetails ? uniqueObjects : undefined,
  };
}

/**
 * Detect DS-Replication-Get-Changes rights (DCSync capability)
 *
 * These rights allow extracting password hashes from the domain.
 *
 * @param aclEntries - Array of ACL entries
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for ACL_DS_REPLICATION_GET_CHANGES
 */
export function detectAclDsReplicationGetChanges(
  aclEntries: AclEntry[],
  includeDetails: boolean
): Finding {
  // DS-Replication-Get-Changes: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
  // DS-Replication-Get-Changes-All: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
  const REPLICATION_GUIDS = [
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',
  ];

  const affected = aclEntries.filter((ace) => {
    return (
      ace.objectType && REPLICATION_GUIDS.includes(ace.objectType.toLowerCase())
    );
  });

  const uniqueObjects = getUniqueObjects(affected);
  const totalInstances = affected.length;

  return {
    type: 'ACL_DS_REPLICATION_GET_CHANGES',
    severity: 'critical',
    category: 'permissions',
    title: 'DS-Replication-Get-Changes Rights (DCSync)',
    description:
      'Non-standard principals with directory replication rights. ' +
      'Enables DCSync attacks to extract all password hashes from the domain.',
    count: uniqueObjects.length,
    totalInstances: totalInstances !== uniqueObjects.length ? totalInstances : undefined,
    affectedEntities: includeDetails ? uniqueObjects : undefined,
    details: {
      risk: 'Complete domain compromise through password hash extraction.',
      recommendation: 'Remove replication rights from all non-DC accounts.',
    },
  };
}

/**
 * Detect User-Force-Change-Password rights
 *
 * This right allows resetting user passwords without knowing the current password.
 *
 * @param aclEntries - Array of ACL entries
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for ACL_USER_FORCE_CHANGE_PASSWORD
 */
export function detectAclUserForceChangePassword(
  aclEntries: AclEntry[],
  includeDetails: boolean
): Finding {
  // User-Force-Change-Password: 00299570-246d-11d0-a768-00aa006e0529
  const FORCE_CHANGE_PASSWORD_GUID = '00299570-246d-11d0-a768-00aa006e0529';

  const affected = aclEntries.filter((ace) => {
    return ace.objectType?.toLowerCase() === FORCE_CHANGE_PASSWORD_GUID;
  });

  const uniqueObjects = getUniqueObjects(affected);
  const totalInstances = affected.length;

  return {
    type: 'ACL_USER_FORCE_CHANGE_PASSWORD',
    severity: 'medium',
    category: 'permissions',
    title: 'User-Force-Change-Password Rights',
    description:
      'Principals with rights to force password change on user accounts. ' +
      'Can reset passwords to take over accounts.',
    count: uniqueObjects.length,
    totalInstances: totalInstances !== uniqueObjects.length ? totalInstances : undefined,
    affectedEntities: includeDetails ? uniqueObjects : undefined,
  };
}

/**
 * Detect Validated-Write-DNS rights on computers
 *
 * This right allows modifying DNS records for computers.
 *
 * @param aclEntries - Array of ACL entries
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for ACL_COMPUTER_WRITE_VALIDATED_DNS
 */
export function detectAclComputerWriteValidatedDns(
  aclEntries: AclEntry[],
  includeDetails: boolean
): Finding {
  // Validated-Write to DNS-Host-Name: 72e39547-7b18-11d1-adef-00c04fd8d5cd
  const VALIDATED_DNS_GUID = '72e39547-7b18-11d1-adef-00c04fd8d5cd';

  const affected = aclEntries.filter((ace) => {
    const isComputerObject = ace.objectDn.toLowerCase().includes('cn=computers');
    const hasDnsRight = ace.objectType?.toLowerCase() === VALIDATED_DNS_GUID;
    return isComputerObject && hasDnsRight;
  });

  const uniqueObjects = getUniqueObjects(affected);
  const totalInstances = affected.length;

  return {
    type: 'ACL_COMPUTER_WRITE_VALIDATED_DNS',
    severity: 'medium',
    category: 'permissions',
    title: 'Validated-Write-DNS on Computers',
    description:
      'Principals with rights to modify DNS host names on computer objects. ' +
      'Can be used for DNS spoofing and MITM attacks.',
    count: uniqueObjects.length,
    totalInstances: totalInstances !== uniqueObjects.length ? totalInstances : undefined,
    affectedEntities: includeDetails ? uniqueObjects : undefined,
  };
}

/**
 * Check for GenericAll permission on computer objects
 * PingCastle: Computer_ACL_GenericAll
 *
 * @param aclEntries - Array of ACL entries
 * @param includeDetails - Whether to include affected entity details
 * @param computerDns - Optional array of computer DNs for accurate matching
 */
export function detectComputerAclGenericAll(
  aclEntries: AclEntry[],
  includeDetails: boolean,
  computerDns?: string[]
): Finding {
  // GENERIC_ALL raw value
  const GENERIC_ALL = 0x10000000;
  // Full control mask for AD objects (all specific AD rights + standard rights)
  const AD_FULL_CONTROL = 0x000f01ff;

  // Build a Set of lowercase computer DNs for fast lookup
  const computerDnSet = new Set(
    computerDns ? computerDns.map((dn) => dn.toLowerCase()) : []
  );

  // Filter ACLs targeting computer objects
  const computerAcls = aclEntries.filter((ace) => {
    const dn = ace.objectDn.toLowerCase();

    // If we have a list of computer DNs, use exact matching
    if (computerDnSet.size > 0) {
      return computerDnSet.has(dn);
    }

    // Fallback: heuristic detection (less accurate)
    // Computer accounts end with $ in their sAMAccountName (which may appear in CN)
    const cnMatch = dn.match(/cn=([^,]+)/i);
    if (cnMatch && cnMatch[1] && cnMatch[1].endsWith('$')) {
      return true;
    }
    // Also check for computer-related OUs
    return (
      dn.includes('ou=computers') ||
      dn.includes('ou=workstations') ||
      dn.includes('ou=servers') ||
      dn.includes('cn=computers,')
    );
  });

  const affected = computerAcls.filter((ace) => {
    // Check for raw GENERIC_ALL
    if ((ace.accessMask & GENERIC_ALL) !== 0) return true;
    // Check for Full Control (GENERIC_ALL mapped to AD rights)
    return (ace.accessMask & AD_FULL_CONTROL) === AD_FULL_CONTROL;
  });

  const uniqueObjects = getUniqueObjects(affected);
  const totalInstances = affected.length;

  return {
    type: 'COMPUTER_ACL_GENERICALL',
    severity: 'high',
    category: 'permissions',
    title: 'Computer ACL GenericAll',
    description:
      'GenericAll permission on computer objects. Attacker with this permission can take over the computer, ' +
      'configure Resource-Based Constrained Delegation (RBCD), or extract credentials.',
    count: uniqueObjects.length,
    totalInstances: totalInstances !== uniqueObjects.length ? totalInstances : undefined,
    affectedEntities: includeDetails ? uniqueObjects : undefined,
  };
}

/**
 * Detect all permission-related vulnerabilities
 *
 * @param aclEntries - Array of ACL entries
 * @param includeDetails - Whether to include affected entity details
 * @param computerDns - Optional array of computer DNs for accurate COMPUTER_ACL_GENERICALL detection
 */
export function detectPermissionsVulnerabilities(
  aclEntries: AclEntry[],
  includeDetails: boolean,
  computerDns?: string[]
): Finding[] {
  return [
    // High
    detectAclGenericAll(aclEntries, includeDetails),
    detectComputerAclGenericAll(aclEntries, includeDetails, computerDns),
    detectAclWriteDacl(aclEntries, includeDetails),
    detectAclWriteOwner(aclEntries, includeDetails),
    // Medium
    detectAclGenericWrite(aclEntries, includeDetails),
    detectAclForceChangePassword(aclEntries, includeDetails),
    detectEveryoneInAcl(aclEntries, includeDetails),
    detectWriteSpnAbuse(aclEntries, includeDetails),
    detectGpoLinkPoisoning(aclEntries, includeDetails),
    detectAdminSdHolderBackdoor(aclEntries, includeDetails),
    // Phase 4: Advanced ACL detections
    detectAclSelfMembership(aclEntries, includeDetails),
    detectAclAddMember(aclEntries, includeDetails),
    detectAclWritePropertyExtended(aclEntries, includeDetails),
    detectAclDsReplicationGetChanges(aclEntries, includeDetails),
    detectAclUserForceChangePassword(aclEntries, includeDetails),
    detectAclComputerWriteValidatedDns(aclEntries, includeDetails),
  ].filter((finding) => finding.count > 0);
}
