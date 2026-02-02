/**
 * GPO Security Vulnerability Detector
 *
 * Analyzes Group Policy Objects for security misconfigurations.
 *
 * Vulnerabilities detected (9):
 * CRITICAL (1) - Phase 4:
 * - GPO_PASSWORD_IN_SYSVOL: Passwords found in GPO preferences
 *
 * HIGH (2):
 * - GPO_DANGEROUS_PERMISSIONS: Non-admin can edit GPO linked to sensitive OUs
 * - GPO_WEAK_PASSWORD_POLICY: GPO with password length < 12 characters
 *
 * MEDIUM (5):
 * - GPO_LAPS_NOT_DEPLOYED: No LAPS deployment GPO found
 * - GPO_DISABLED_BUT_LINKED: GPO disabled but still linked
 * - GPO_NO_SECURITY_FILTERING: GPO without security filtering
 * - GPO_AUTHENTICATED_USERS_APPLY: GPO applies to all Authenticated Users
 * - GPO_ORPHANED: Orphaned GPO (Phase 4)
 *
 * LOW (1):
 * - GPO_UNLINKED: GPO exists but not linked anywhere
 */

import { Finding } from '../../../../types/finding.types';
import {
  ADGPO,
  GPOLink,
  GPOAclEntry,
  GPO_FLAG_ALL_DISABLED,
  LAPS_CSE_GUID,
  LAPS_LEGACY_CSE_GUID,
} from '../../../../types/gpo.types';

// Well-known SIDs for security filtering analysis
const SID_AUTHENTICATED_USERS = 'S-1-5-11';
const SID_EVERYONE = 'S-1-1-0';
const SID_DOMAIN_COMPUTERS = '-515'; // Ends with this RID

// "Apply Group Policy" extended right GUID
const APPLY_GROUP_POLICY_RIGHT = 0x00000004; // Read + Execute equivalent for GPO

/**
 * Check if GPO has LAPS Client-Side Extension
 */
function hasLapsCse(gpo: ADGPO): boolean {
  const extensions = gpo.gPCMachineExtensionNames || '';
  return extensions.includes(LAPS_CSE_GUID) || extensions.includes(LAPS_LEGACY_CSE_GUID);
}

/**
 * GPO_DANGEROUS_PERMISSIONS: Non-admin can edit GPO
 * Note: Requires ACL analysis - placeholder for now
 */
export function detectGpoDangerousPermissions(
  gpos: ADGPO[],
  _links: GPOLink[],
  _includeDetails: boolean
): Finding {
  // Would analyze nTSecurityDescriptor on GPO objects for:
  // - GenericAll, GenericWrite, WriteDacl, WriteOwner, WriteProperty
  // granted to non-admin principals (Domain Users, Authenticated Users, etc.)

  return {
    type: 'GPO_DANGEROUS_PERMISSIONS',
    severity: 'high',
    category: 'gpo',
    title: 'GPO Permissions Review Required',
    description:
      'Group Policy Objects should be reviewed for overly permissive ACLs that allow non-administrators to modify GPO settings.',
    count: 0, // Placeholder until ACL analysis implemented
    affectedEntities: undefined,
    details: {
      note: 'Manual review of GPO ACLs recommended. Check for non-admin principals with write access.',
      gposToReview: gpos.length,
    },
  };
}

/**
 * GPO_LAPS_NOT_DEPLOYED: No LAPS deployment GPO found
 */
export function detectGpoLapsNotDeployed(
  gpos: ADGPO[],
  links: GPOLink[],
  _includeDetails: boolean
): Finding {
  // Check if any GPO has LAPS CSE and is linked
  const lapsGpos = gpos.filter((gpo) => hasLapsCse(gpo));
  const linkedLapsGpos = lapsGpos.filter((gpo) =>
    links.some((link) => link.gpoGuid.toLowerCase() === gpo.cn.toLowerCase() && !link.disabled)
  );

  const noLapsDeployed = linkedLapsGpos.length === 0;

  return {
    type: 'GPO_LAPS_NOT_DEPLOYED',
    severity: 'medium',
    category: 'gpo',
    title: 'LAPS Not Deployed via GPO',
    description:
      'No active Group Policy Object was found deploying LAPS (Local Administrator Password Solution). This leaves local admin passwords vulnerable to reuse attacks.',
    count: noLapsDeployed ? 1 : 0,
    affectedEntities: undefined,
    details: {
      lapsGposFound: lapsGpos.length,
      linkedLapsGpos: linkedLapsGpos.length,
      note: noLapsDeployed
        ? 'LAPS not deployed - local admin passwords are not being rotated.'
        : 'LAPS is deployed via GPO.',
      recommendation: noLapsDeployed
        ? 'Deploy LAPS via GPO to manage local administrator passwords.'
        : undefined,
    },
  };
}

/**
 * GPO_WEAK_PASSWORD_POLICY: GPO with weak password settings
 * Note: Requires reading GptTmpl.inf via SMB - check domain policy instead
 */
export function detectGpoWeakPasswordPolicy(
  _gpos: ADGPO[],
  _links: GPOLink[],
  domainPasswordPolicy: { minPasswordLength?: number } | null,
  includeDetails: boolean
): Finding {
  const minLength = domainPasswordPolicy?.minPasswordLength ?? 0;
  const isWeak = minLength < 12;

  return {
    type: 'GPO_WEAK_PASSWORD_POLICY',
    severity: 'medium',
    category: 'gpo',
    title: 'Weak Password Policy',
    description: `Domain password policy requires only ${minLength} characters minimum. Microsoft recommends at least 12 characters for standard accounts, 14+ for privileged accounts.`,
    count: isWeak ? 1 : 0,
    affectedEntities: includeDetails && isWeak ? ['Default Domain Policy'] : undefined,
    details: isWeak
      ? {
          currentMinLength: minLength,
          recommendedMinLength: 12,
        }
      : undefined,
  };
}

/**
 * GPO_UNLINKED: GPO exists but not linked anywhere
 */
export function detectGpoUnlinked(
  gpos: ADGPO[],
  links: GPOLink[],
  includeDetails: boolean
): Finding {
  // Find GPOs that have no links
  const linkedGuids = new Set(links.map((l) => l.gpoGuid.toLowerCase()));
  const unlinkedGpos = gpos.filter((gpo) => !linkedGuids.has(gpo.cn.toLowerCase()));

  // Exclude Default Domain Policy and Default Domain Controllers Policy
  const excludeGuids = [
    '31B2F340-016D-11D2-945F-00C04FB984F9', // Default Domain Policy
    '6AC1786C-016F-11D2-945F-00C04FB984F9', // Default Domain Controllers Policy
  ];

  const relevantUnlinked = unlinkedGpos.filter(
    (gpo) => !excludeGuids.some((guid) => gpo.cn.toUpperCase().includes(guid))
  );

  return {
    type: 'GPO_UNLINKED',
    severity: 'low',
    category: 'gpo',
    title: 'Unlinked Group Policy Objects',
    description:
      'GPOs exist that are not linked to any OU, domain, or site. These may be orphaned or indicate incomplete deployment.',
    count: relevantUnlinked.length,
    affectedEntities: includeDetails
      ? relevantUnlinked.map((gpo) => gpo.displayName || gpo.cn)
      : undefined,
  };
}

/**
 * GPO_DISABLED_BUT_LINKED: GPO is disabled but still linked
 */
export function detectGpoDisabledButLinked(
  gpos: ADGPO[],
  links: GPOLink[],
  includeDetails: boolean
): Finding {
  // Find GPOs that are disabled (flags = 3) but have active links
  const disabledGpos = gpos.filter((gpo) => gpo.flags === GPO_FLAG_ALL_DISABLED);

  const disabledButLinked = disabledGpos.filter((gpo) =>
    links.some((link) => link.gpoGuid.toLowerCase() === gpo.cn.toLowerCase() && !link.disabled)
  );

  return {
    type: 'GPO_DISABLED_BUT_LINKED',
    severity: 'medium',
    category: 'gpo',
    title: 'Disabled GPO Still Linked',
    description:
      'GPOs are disabled (both user and computer settings) but remain linked. This may indicate configuration drift or incomplete changes.',
    count: disabledButLinked.length,
    affectedEntities: includeDetails
      ? disabledButLinked.map((gpo) => gpo.displayName || gpo.cn)
      : undefined,
  };
}

/**
 * GPO_NO_SECURITY_FILTERING: GPO without explicit security filtering
 * GPO applies to all objects in the linked OU without restrictions
 */
export function detectGpoNoSecurityFiltering(
  gpos: ADGPO[],
  links: GPOLink[],
  gpoAcls: GPOAclEntry[],
  includeDetails: boolean
): Finding {
  // Get linked GPO GUIDs
  const linkedGuids = new Set(
    links.filter((l) => !l.disabled).map((l) => l.gpoGuid.toLowerCase())
  );

  // Find GPOs that are linked but have no security filtering
  // Security filtering = only specific groups have "Apply Group Policy" right
  // No filtering = Authenticated Users or Everyone has Apply right
  const noFiltering: ADGPO[] = [];

  for (const gpo of gpos) {
    // Only check linked GPOs
    if (!linkedGuids.has(gpo.cn.toLowerCase())) continue;

    // Get ACLs for this GPO
    const aclsForGpo = gpoAcls.filter(
      (acl) => acl.gpoDn.toLowerCase() === gpo.dn.toLowerCase()
    );

    // If no ACL data, skip (can't determine)
    if (aclsForGpo.length === 0) continue;

    // Check if Authenticated Users or Everyone has Apply permission
    const hasUnrestrictedApply = aclsForGpo.some(
      (acl) =>
        (acl.trusteeSid === SID_AUTHENTICATED_USERS || acl.trusteeSid === SID_EVERYONE) &&
        (acl.accessMask & APPLY_GROUP_POLICY_RIGHT) !== 0
    );

    // Check if there's any specific group filtering (exclude auth users and everyone)
    const hasSpecificFiltering = aclsForGpo.some(
      (acl) =>
        acl.trusteeSid !== SID_AUTHENTICATED_USERS &&
        acl.trusteeSid !== SID_EVERYONE &&
        !acl.trusteeSid.endsWith(SID_DOMAIN_COMPUTERS) &&
        (acl.accessMask & APPLY_GROUP_POLICY_RIGHT) !== 0
    );

    // No filtering if auth users/everyone can apply and no specific groups defined
    if (hasUnrestrictedApply && !hasSpecificFiltering) {
      noFiltering.push(gpo);
    }
  }

  return {
    type: 'GPO_NO_SECURITY_FILTERING',
    severity: 'medium',
    category: 'gpo',
    title: 'GPO Without Security Filtering',
    description:
      'GPOs that apply to all Authenticated Users or Everyone without specific security filtering. Consider restricting GPO application to specific groups.',
    count: noFiltering.length,
    affectedEntities: includeDetails
      ? noFiltering.map((gpo) => gpo.displayName || gpo.cn)
      : undefined,
    details:
      noFiltering.length > 0
        ? {
            recommendation:
              'Apply security filtering to restrict GPO application to specific groups.',
          }
        : undefined,
  };
}

/**
 * GPO_AUTHENTICATED_USERS_APPLY: GPO explicitly grants Apply to Authenticated Users
 * This is the default but may be unintended for sensitive GPOs
 */
export function detectGpoAuthenticatedUsersApply(
  gpos: ADGPO[],
  links: GPOLink[],
  gpoAcls: GPOAclEntry[],
  includeDetails: boolean
): Finding {
  // Get linked GPO GUIDs
  const linkedGuids = new Set(
    links.filter((l) => !l.disabled).map((l) => l.gpoGuid.toLowerCase())
  );

  // Find GPOs where Authenticated Users has explicit Apply permission
  const authUsersApply: ADGPO[] = [];

  for (const gpo of gpos) {
    // Only check linked GPOs
    if (!linkedGuids.has(gpo.cn.toLowerCase())) continue;

    // Get ACLs for this GPO
    const aclsForGpo = gpoAcls.filter(
      (acl) => acl.gpoDn.toLowerCase() === gpo.dn.toLowerCase()
    );

    // If no ACL data, skip
    if (aclsForGpo.length === 0) continue;

    // Check if Authenticated Users specifically has Apply permission
    const authUsersHasApply = aclsForGpo.some(
      (acl) =>
        acl.trusteeSid === SID_AUTHENTICATED_USERS &&
        (acl.accessMask & APPLY_GROUP_POLICY_RIGHT) !== 0
    );

    if (authUsersHasApply) {
      authUsersApply.push(gpo);
    }
  }

  return {
    type: 'GPO_AUTHENTICATED_USERS_APPLY',
    severity: 'medium',
    category: 'gpo',
    title: 'GPO Applies to All Authenticated Users',
    description:
      'GPOs with Authenticated Users granted the "Apply Group Policy" permission. This is the default but may be too broad for sensitive policies.',
    count: authUsersApply.length,
    affectedEntities: includeDetails
      ? authUsersApply.map((gpo) => gpo.displayName || gpo.cn)
      : undefined,
    details:
      authUsersApply.length > 0
        ? {
            recommendation:
              'Review if all GPOs should apply to all users. Consider using security filtering for sensitive policies.',
            note: 'This is informational - Authenticated Users is the default.',
          }
        : undefined,
  };
}

/**
 * Detect GPOs with passwords stored in SYSVOL (cPassword)
 *
 * MS14-025 patched this, but old GPOs may still contain cleartext passwords
 * in Groups.xml, Services.xml, Scheduledtasks.xml, etc.
 *
 * @param gpos - Array of GPOs
 * @param _links - Array of GPO links (not used)
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for GPO_PASSWORD_IN_SYSVOL
 */
export function detectGpoPasswordInSysvol(
  gpos: ADGPO[],
  _links: GPOLink[],
  includeDetails: boolean
): Finding {
  // Check GPO flags or attributes that might indicate password presence
  // This would ideally need SYSVOL file content reading
  // For now, check for GPOs with "cpassword" mentioned or old-style preferences
  const affected = gpos.filter((gpo) => {
    const gpoName = (gpo.displayName || gpo.cn || '').toLowerCase();
    const gpoPath = (gpo.gPCFileSysPath || '').toLowerCase();

    // GPOs that commonly contain passwords
    const riskyPatterns = [
      'password',
      'credential',
      'local admin',
      'service account',
      'scheduled task',
      'drive map',
    ];

    return riskyPatterns.some(
      (pattern) => gpoName.includes(pattern) || gpoPath.includes(pattern)
    );
  });

  return {
    type: 'GPO_PASSWORD_IN_SYSVOL',
    severity: 'critical',
    category: 'gpo',
    title: 'Potential Passwords in GPO SYSVOL',
    description:
      'GPOs that may contain cleartext passwords in SYSVOL (cPassword vulnerability MS14-025). ' +
      'Group Policy Preferences stored passwords that can be easily decrypted.',
    count: affected.length,
    affectedEntities: includeDetails
      ? affected.map((g) => g.displayName || g.cn || g.dn)
      : undefined,
    details: {
      note: affected.length > 0
        ? `Found ${affected.length} GPO(s) with names suggesting password storage. Manual SYSVOL scan required.`
        : 'No GPOs with suspicious names found. Manual SYSVOL scan still recommended.',
      recommendation:
        'Scan SYSVOL for Groups.xml, Services.xml, ScheduledTasks.xml, DataSources.xml containing cpassword. ' +
        'Use tools like Get-GPPPassword or gpp-decrypt.',
      reference: 'MS14-025',
      gposScanned: gpos.length,
    },
  };
}

/**
 * Detect orphaned GPOs
 *
 * GPOs that exist in AD but have missing SYSVOL content, or vice versa.
 *
 * @param gpos - Array of GPOs
 * @param _links - Array of GPO links (not used)
 * @param includeDetails - Whether to include affected entity details
 * @returns Finding for GPO_ORPHANED
 */
export function detectGpoOrphaned(
  gpos: ADGPO[],
  _links: GPOLink[],
  includeDetails: boolean
): Finding {
  // Check for GPOs with potential orphan indicators
  // A proper check would compare AD GPOs vs SYSVOL folders
  const affected = gpos.filter((gpo) => {
    // Missing SYSVOL path indicates potential orphan
    const hasSysvolPath = gpo.gPCFileSysPath && gpo.gPCFileSysPath.length > 0;
    // Missing version might indicate corruption
    const hasVersion = gpo.versionNumber !== undefined && gpo.versionNumber > 0;
    // Check for obviously broken GPOs
    const hasName = gpo.displayName || gpo.cn;

    return !hasSysvolPath || !hasVersion || !hasName;
  });

  return {
    type: 'GPO_ORPHANED',
    severity: 'medium',
    category: 'gpo',
    title: 'Potentially Orphaned GPOs',
    description:
      'GPOs that may be orphaned (missing SYSVOL content or AD object). ' +
      'Orphaned GPOs can cause processing errors and may indicate tampering.',
    count: affected.length,
    affectedEntities: includeDetails
      ? affected.map((g) => g.displayName || g.cn || g.dn)
      : undefined,
    details: {
      recommendation:
        'Compare AD GPOs with SYSVOL folders. Use gpotool.exe or Get-GPO to identify orphans. ' +
        'Delete orphaned GPOs after verification.',
    },
  };
}

/**
 * Aggregate function: Detect all GPO vulnerabilities
 */
export function detectGpoVulnerabilities(
  gpos: ADGPO[],
  links: GPOLink[],
  domainPasswordPolicy: { minPasswordLength?: number } | null,
  includeDetails: boolean,
  gpoAcls: GPOAclEntry[] = []
): Finding[] {
  return [
    detectGpoDangerousPermissions(gpos, links, includeDetails),
    detectGpoLapsNotDeployed(gpos, links, includeDetails),
    detectGpoWeakPasswordPolicy(gpos, links, domainPasswordPolicy, includeDetails),
    detectGpoUnlinked(gpos, links, includeDetails),
    detectGpoDisabledButLinked(gpos, links, includeDetails),
    detectGpoNoSecurityFiltering(gpos, links, gpoAcls, includeDetails),
    detectGpoAuthenticatedUsersApply(gpos, links, gpoAcls, includeDetails),
    // Phase 4: Advanced GPO detections
    detectGpoPasswordInSysvol(gpos, links, includeDetails),
    detectGpoOrphaned(gpos, links, includeDetails),
  ].filter((finding) => finding.count > 0 || finding.details?.['note']);
}
