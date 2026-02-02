/**
 * Active Directory Audit Service
 *
 * Orchestrates AD vulnerability detection across 85 checks in 7 categories
 * Story 1.7: AD Vulnerability Detection Engine
 *
 * Architecture:
 * 1. Collect AD data (users, groups, computers, domain, templates, CAs, ACLs)
 * 2. Run all detector categories in parallel
 * 3. Aggregate findings
 * 4. Calculate security score
 * 5. Return audit results
 */

import { LDAPProvider } from '../../providers/ldap/ldap.provider';
import { ADUser, ADGroup, ADComputer, ADDomain, AclEntry } from '../../types/ad.types';
import { LDAPControl } from '../../providers/interfaces/ILDAPProvider';
import { parseSecurityDescriptor, resetParseStats } from '../../providers/ldap/acl-parser';
import { Finding } from '../../types/finding.types';
import { calculateSecurityScore, SecurityScore } from './scoring.service';
import { DomainConfig } from './response-formatter';
import { logger } from '../../utils/logger';
import { SMBProvider, formatKerberosPolicy, getDefaultKerberosPolicy, SMBConfig, FormattedKerberosPolicy, GpoSecuritySettings } from '../../providers/smb/smb.provider';
import { Client as LDAPClient } from 'ldapts';
import { SMBConfig as AppSMBConfig, LDAPConfig } from '../../types/config.types';

// Import all AD detectors
import {
  detectPasswordVulnerabilities,
  detectKerberosVulnerabilities,
  detectAccountsVulnerabilities,
  detectGroupsVulnerabilities,
  detectComputersVulnerabilities,
  detectAdvancedVulnerabilities,
  detectPermissionsVulnerabilities,
  detectAdcsVulnerabilities,
  detectGpoVulnerabilities,
  detectTrustVulnerabilities,
  detectAttackPathVulnerabilities,
  detectMonitoringVulnerabilities,
} from './detectors/ad';

// Import new types
import { ADCSCertificateTemplate, ADCSCertificateAuthority } from '../../types/adcs.types';
import { ADGPO, GPOLink } from '../../types/gpo.types';
import { ADTrustExtended, parseTrustAttributes, parseTrustDirection, parseTrustType } from '../../types/trust.types';
import { computeAttackGraph } from './attack-graph.service';
import { AttackGraphExport } from '../../types/attack-graph.types';

/**
 * Create LDAP_SERVER_SD_FLAGS_OID control for reading Security Descriptors
 *
 * This control is required to read ntSecurityDescriptor attribute.
 * Flags specify which parts of the SD to return:
 * - OWNER_SECURITY_INFORMATION (0x00000001)
 * - GROUP_SECURITY_INFORMATION (0x00000002)
 * - DACL_SECURITY_INFORMATION (0x00000004)
 * - SACL_SECURITY_INFORMATION (0x00000008)
 */
function createSDFlagsControl(): LDAPControl {
  const LDAP_SERVER_SD_FLAGS_OID = '1.2.840.113556.1.4.801';

  // Request OWNER + GROUP + DACL (0x07)
  // We don't request SACL (0x08) as it requires special permissions
  const SD_FLAGS = 0x00000007;

  // Encode as BER INTEGER: 02 01 07
  // Tag: 0x02 (INTEGER), Length: 0x01 (1 byte), Value: 0x07
  const buffer = Buffer.from([0x02, 0x01, SD_FLAGS]);

  return {
    oid: LDAP_SERVER_SD_FLAGS_OID,
    critical: false,
    value: buffer,
  };
}

/**
 * Audit options
 */
export interface AuditOptions {
  /**
   * Include detailed entity DNs in findings
   */
  includeDetails?: boolean;

  /**
   * Maximum number of users to fetch (for testing)
   */
  maxUsers?: number;

  /**
   * Maximum number of groups to fetch (for testing)
   */
  maxGroups?: number;

  /**
   * Maximum number of computers to fetch (for testing)
   */
  maxComputers?: number;
}

/**
 * Audit result
 */
export interface AuditResult {
  /**
   * Overall security score
   */
  score: SecurityScore;

  /**
   * All vulnerability findings
   */
  findings: Finding[];

  /**
   * Statistics
   */
  stats: {
    totalUsers: number;
    enabledUsers: number;
    disabledUsers: number;
    totalGroups: number;
    totalComputers: number;
    enabledComputers: number;
    disabledComputers: number;
    totalOUs: number;
    totalFindings: number;
    executionTimeMs: number;
    ldapUrl?: string; // For debugging which DC we connected to
  };

  /**
   * Timestamp
   */
  timestamp: Date;

  /**
   * Domain configuration (password policy, domain info, trusts, GPOs)
   */
  domainConfig?: DomainConfig;

  /**
   * Attack graph data for visualization
   */
  attackGraph?: AttackGraphExport;
}

/**
 * Convert Windows FILETIME to JavaScript Date
 * FILETIME is a 64-bit value representing 100-nanosecond intervals since January 1, 1601 UTC
 *
 * @param filetime Windows FILETIME value (string or number)
 * @returns JavaScript Date object or undefined
 */
function convertFiletimeToDate(filetime: any): Date | undefined {
  if (!filetime) return undefined;

  // Parse the filetime value
  let filetimeNum: number;
  if (typeof filetime === 'string') {
    filetimeNum = parseInt(filetime, 10);
  } else if (typeof filetime === 'number') {
    filetimeNum = filetime;
  } else {
    return undefined;
  }

  // Check for invalid values
  // 0 or very large values (like 0x7FFFFFFFFFFFFFFF) indicate "never" or invalid
  if (filetimeNum === 0 || filetimeNum >= 9223372036854775807) {
    return undefined;
  }

  // Convert from 100-nanosecond intervals to milliseconds
  const milliseconds = filetimeNum / 10000;

  // Offset between Windows epoch (1601) and Unix epoch (1970) in milliseconds
  const epochOffset = 11644473600000;

  // Calculate Unix timestamp and create Date
  const unixTimestamp = milliseconds - epochOffset;

  // Validate the timestamp is reasonable (not negative, not too far in future)
  if (unixTimestamp < 0 || unixTimestamp > Date.now() + 100 * 365 * 24 * 60 * 60 * 1000) {
    return undefined;
  }

  return new Date(unixTimestamp);
}

/**
 * Active Directory Audit Service
 */
export class ADAuditService {
  private smbConfig?: { smb: AppSMBConfig; ldap: LDAPConfig };

  constructor(private ldapProvider: LDAPProvider, smbConfig?: { smb: AppSMBConfig; ldap: LDAPConfig }) {
    this.smbConfig = smbConfig;
  }

  /**
   * Run full AD security audit
   *
   * @param options Audit options
   * @returns Audit results with findings and security score
   */
  async runAudit(options: AuditOptions = {}): Promise<AuditResult> {
    const startTime = Date.now();
    const { includeDetails = false, maxUsers, maxGroups, maxComputers } = options;
    const baseDN = this.ldapProvider.getBaseDN();

    // 1. Collect AD data
    const [users, groups, computers, domain, ouCount] = await Promise.all([
      this.fetchUsers(maxUsers),
      this.fetchGroups(maxGroups),
      this.fetchComputers(maxComputers),
      this.fetchDomain(),
      this.fetchOUCount(),
    ]);

    // 2. Collect additional data for advanced detectors
    // Fetch ADCS, GPO, and Trust data in parallel
    const [certTemplates, certAuthorities, gpoData, trustsExtended, aclEntries, anonymousAccessAllowed, gpoSecuritySettings] = await Promise.all([
      this.fetchCertificateTemplates(),
      this.fetchCertificateAuthorities(),
      this.fetchGPOsWithAcls(),
      this.fetchTrustsExtended(),
      this.fetchAcls(users, groups, computers),
      this.testAnonymousLdapAccess(),
      this.fetchGpoSecuritySettings(),
    ]);

    // Legacy placeholders for advanced detector (kept for backward compatibility)
    const templates: any[] = certTemplates; // ADCS certificate templates
    const cas: any[] = certAuthorities; // ADCS Certificate Authorities
    const fsps: any[] = []; // Foreign Security Principals

    // 3. Run all detector categories
    const findings: Finding[] = [];

    // Run detectors in parallel for better performance
    const detectorResults = await Promise.all([
      Promise.resolve(detectPasswordVulnerabilities(users, includeDetails)),
      Promise.resolve(detectKerberosVulnerabilities(users, includeDetails)),
      Promise.resolve(detectAccountsVulnerabilities(users, includeDetails)),
      Promise.resolve(detectGroupsVulnerabilities(users, groups, includeDetails)),
      Promise.resolve(detectComputersVulnerabilities(computers, includeDetails)),
      Promise.resolve(
        detectAdvancedVulnerabilities(users, computers, domain, templates, cas, fsps, includeDetails, {
          gpoSettings: gpoSecuritySettings,
          anonymousAccessAllowed,
        })
      ),
      Promise.resolve(detectPermissionsVulnerabilities(aclEntries, includeDetails, computers.map((c) => c.dn))),
      // New detectors: ADCS, GPO, Trusts
      Promise.resolve(detectAdcsVulnerabilities(certTemplates, certAuthorities, includeDetails)),
      Promise.resolve(
        detectGpoVulnerabilities(
          gpoData.gpos,
          gpoData.links,
          domain ? { minPasswordLength: domain['minPwdLength'] as number | undefined } : null,
          includeDetails,
          gpoData.gpoAcls
        )
      ),
      Promise.resolve(detectTrustVulnerabilities(trustsExtended, includeDetails)),
      // Attack Paths detector (Phase 2A)
      Promise.resolve(
        detectAttackPathVulnerabilities(
          users,
          groups,
          computers,
          aclEntries,
          gpoData.gpos,
          trustsExtended,
          certTemplates,
          includeDetails
        )
      ),
      // Monitoring detector (Phase 2B)
      Promise.resolve(
        detectMonitoringVulnerabilities(users, groups, domain, includeDetails, {
          gpoSettings: gpoSecuritySettings,
        })
      ),
    ]);

    // Flatten all findings
    detectorResults.forEach((categoryFindings) => {
      findings.push(...categoryFindings);
    });

    // 4. Calculate security score
    const score = calculateSecurityScore(findings, users.length);

    // 5. Fetch domain configuration
    const domainConfig = await this.fetchDomainConfig(domain);

    // 6. Compute attack graph
    logger.info('Computing attack graph...');
    const attackGraphStartTime = Date.now();
    const attackGraph = computeAttackGraph(
      users,
      groups,
      computers,
      aclEntries,
      certTemplates,
      gpoData.gpos,
      {
        name: domainConfig?.domainInfo?.domainName || this.extractDomainNameFromDN(baseDN),
        sid: undefined, // Will be auto-detected
      },
      500 // maxPaths
    );
    logger.info(`Attack graph computed in ${Date.now() - attackGraphStartTime}ms: ${attackGraph.paths.length} paths found`);

    // 7. Build result
    const executionTimeMs = Date.now() - startTime;

    // Calculate enabled/disabled user counts (UAC flag 0x2 = ACCOUNTDISABLE)
    const disabledUsers = users.filter((u) => ((u.userAccountControl ?? 0) & 0x2) !== 0).length;
    const enabledUsers = users.length - disabledUsers;

    // Calculate enabled/disabled computer counts
    const disabledComputers = computers.filter((c) => !c.enabled).length;
    const enabledComputers = computers.length - disabledComputers;

    return {
      score,
      findings,
      stats: {
        totalUsers: users.length,
        enabledUsers,
        disabledUsers,
        totalGroups: groups.length,
        totalComputers: computers.length,
        enabledComputers,
        disabledComputers,
        totalOUs: ouCount,
        totalFindings: findings.length,
        executionTimeMs,
        ldapUrl: this.ldapProvider.getUrl(),
      },
      timestamp: new Date(),
      domainConfig,
      attackGraph,
    };
  }

  /**
   * Test LDAP connection
   *
   * @returns Connection test result
   */
  async testConnection(): Promise<{ success: boolean; message: string }> {
    try {
      return await this.ldapProvider.testConnection();
    } catch (error) {
      return {
        success: false,
        message: error instanceof Error ? error.message : 'Unknown connection error',
      };
    }
  }

  /**
   * Test if anonymous LDAP access is allowed
   * Attempts an anonymous bind to the LDAP server
   *
   * @returns true if anonymous access is allowed
   */
  private async testAnonymousLdapAccess(): Promise<boolean> {
    if (!this.smbConfig?.ldap) {
      return false;
    }

    const { ldap } = this.smbConfig;
    // Extract host and port from LDAP URL
    const urlMatch = ldap.url.match(/ldaps?:\/\/([^:/]+)(?::(\d+))?/i);
    if (!urlMatch || !urlMatch[1]) {
      return false;
    }

    const host = urlMatch[1];
    const isLdaps = ldap.url.toLowerCase().startsWith('ldaps://');
    const defaultPort = isLdaps ? 636 : 389;
    const port = urlMatch[2] ? parseInt(urlMatch[2], 10) : defaultPort;

    try {
      // Create a separate client for anonymous bind test
      const anonClient = new LDAPClient({
        url: `ldap://${host}:${port}`,
        timeout: 5000,
        connectTimeout: 5000,
      });

      // Attempt anonymous bind (empty DN and password)
      await anonClient.bind('', '');

      // Try to search for something - if successful, anonymous access is truly allowed
      try {
        await anonClient.search(ldap.baseDN, {
          filter: '(objectClass=domain)',
          attributes: ['dn'],
          scope: 'base',
          sizeLimit: 1,
        });
      } catch {
        // Search failed but bind succeeded - limited anonymous access
      }

      await anonClient.unbind();
      return true;
    } catch {
      // Anonymous bind failed - anonymous access not allowed
      return false;
    }
  }

  /**
   * Fetch users from AD
   */
  private async fetchUsers(maxUsers?: number): Promise<ADUser[]> {
    const baseDN = this.ldapProvider.getBaseDN();
    const filter = '(&(objectClass=user)(objectCategory=person))';
    const attributes = [
      // Identity
      'dn',
      'sAMAccountName',
      'userPrincipalName',
      'displayName',
      'mail',
      // Organization
      'title',
      'department',
      'company',
      'manager',
      'physicalDeliveryOfficeName',
      'description',
      'employeeID',
      'telephoneNumber',
      // Dates
      'whenCreated',
      'whenChanged',
      'lastLogon',
      'pwdLastSet',
      'passwordLastSet',
      'accountExpires',
      // Security
      'badPwdCount',
      'lockoutTime',
      'adminCount',
      'memberOf',
      'userAccountControl',
      // Technical (for detection)
      'servicePrincipalName',
      'msDS-SupportedEncryptionTypes',
      'sIDHistory',
      'msDS-KeyCredentialLink',
      'msDS-AllowedToActOnBehalfOfOtherIdentity',
      'msDS-AllowedToDelegateTo',
      // Unix password attributes (cleartext risk)
      'unixUserPassword',
      'userPassword',
    ];

    const results = await this.ldapProvider.search<any>(baseDN, {
      filter,
      attributes,
      scope: 'sub',
      sizeLimit: maxUsers,
      paged: true, // Enable pagination to fetch all users beyond 1000 limit
    });

    return results.map((entry: any) => ({
      ...entry, // Spread all properties first
      dn: entry.dn,
      sAMAccountName: entry.sAMAccountName as string,
      userPrincipalName: entry.userPrincipalName as string,
      displayName: entry.displayName as string,
      enabled: !((entry.userAccountControl as number) & 0x2), // ACCOUNTDISABLE flag
      passwordLastSet: convertFiletimeToDate(entry.passwordLastSet), // Override with converted dates
      lastLogon: convertFiletimeToDate(entry.lastLogon), // Override with converted dates
      accountExpires: convertFiletimeToDate(entry.accountExpires), // Override with converted dates
      adminCount: entry.adminCount as number,
      // Ensure array fields are always arrays (LDAP returns single value as string)
      memberOf: !entry.memberOf ? [] : Array.isArray(entry.memberOf) ? entry.memberOf : [entry.memberOf],
      servicePrincipalName: !entry.servicePrincipalName
        ? []
        : Array.isArray(entry.servicePrincipalName)
          ? entry.servicePrincipalName
          : [entry.servicePrincipalName],
      userAccountControl: entry.userAccountControl as number,
    }));
  }

  /**
   * Fetch groups from AD
   */
  private async fetchGroups(maxGroups?: number): Promise<ADGroup[]> {
    const baseDN = this.ldapProvider.getBaseDN();
    const filter = '(objectClass=group)';
    const attributes = ['dn', 'sAMAccountName', 'displayName', 'groupType', 'memberOf', 'member'];

    const results = await this.ldapProvider.search<any>(baseDN, {
      filter,
      attributes,
      scope: 'sub',
      sizeLimit: maxGroups,
      paged: true, // Enable pagination to fetch all groups beyond 1000 limit
    });

    return results.map((entry: any) => ({
      ...entry, // Spread all properties first
      dn: entry.dn,
      sAMAccountName: entry.sAMAccountName as string,
      displayName: entry.displayName as string,
      groupType: entry.groupType as number,
      // Ensure array fields are always arrays (LDAP returns single value as string)
      memberOf: !entry.memberOf ? [] : Array.isArray(entry.memberOf) ? entry.memberOf : [entry.memberOf],
      member: !entry.member ? [] : Array.isArray(entry.member) ? entry.member : [entry.member],
    }));
  }

  /**
   * Fetch computers from AD
   */
  private async fetchComputers(maxComputers?: number): Promise<ADComputer[]> {
    const baseDN = this.ldapProvider.getBaseDN();
    const filter = '(objectClass=computer)';
    const attributes = [
      'dn',
      'sAMAccountName',
      'dNSHostName',
      'operatingSystem',
      'operatingSystemVersion',
      'lastLogon',
      'userAccountControl',
      'pwdLastSet',
      'servicePrincipalName',
      'ms-Mcs-AdmPwd',
      'ms-Mcs-AdmPwdExpirationTime', // LAPS expiration (readable even without password rights)
      'msLAPS-Password',
      'msLAPS-PasswordExpirationTime', // Windows LAPS expiration
      'lastLogonTimestamp', // Replicated version of lastLogon
      'msDS-AllowedToDelegateTo',
      'msDS-AllowedToActOnBehalfOfOtherIdentity',
      'msDS-SupportedEncryptionTypes',
      'memberOf',
      'description',
      'whenCreated', // For debugging date issues
      'whenChanged',
      'adminCount',
    ];

    const results = await this.ldapProvider.search<any>(baseDN, {
      filter,
      attributes,
      scope: 'sub',
      sizeLimit: maxComputers,
      paged: true, // Enable pagination to fetch all computers beyond 1000 limit
    });

    return results.map((entry: any) => ({
      ...entry, // Spread all properties first
      dn: entry.dn,
      sAMAccountName: entry.sAMAccountName as string,
      dNSHostName: entry.dNSHostName as string,
      operatingSystem: entry.operatingSystem as string,
      operatingSystemVersion: entry.operatingSystemVersion as string,
      lastLogon: convertFiletimeToDate(entry.lastLogon), // Convert date
      pwdLastSet: convertFiletimeToDate(entry.pwdLastSet), // Convert date
      enabled: !((entry.userAccountControl as number) & 0x2), // ACCOUNTDISABLE flag
      // Ensure array fields are always arrays (LDAP returns single value as string)
      memberOf: !entry.memberOf ? [] : Array.isArray(entry.memberOf) ? entry.memberOf : [entry.memberOf],
      servicePrincipalName: !entry.servicePrincipalName
        ? []
        : Array.isArray(entry.servicePrincipalName)
          ? entry.servicePrincipalName
          : [entry.servicePrincipalName],
    }));
  }

  /**
   * Fetch domain configuration
   */
  private async fetchDomain(): Promise<ADDomain | null> {
    try {
      const baseDN = this.ldapProvider.getBaseDN();
      const filter = '(objectClass=domain)';
      const attributes = [
        'dn',
        'name',
        'msDS-Behavior-Version', // Domain functional level
        'minPwdLength',
        'maxPwdAge',
        'pwdHistoryLength',
        'ms-DS-MachineAccountQuota',
      ];

      const results = await this.ldapProvider.search<any>(baseDN, {
        filter,
        attributes,
        scope: 'base',
      });

      if (results.length === 0) return null;

      const entry: any = results[0];
      const domainFunctionalLevel = entry['msDS-Behavior-Version'] !== undefined
        ? parseInt(entry['msDS-Behavior-Version'], 10)
        : undefined;

      // Fetch forest functional level from Configuration partition
      let forestFunctionalLevel: number | undefined;
      try {
        const configDN = `CN=Partitions,CN=Configuration,${baseDN}`;
        const forestResults = await this.ldapProvider.search<any>(configDN, {
          filter: '(objectClass=crossRefContainer)',
          attributes: ['msDS-Behavior-Version'],
          scope: 'base',
        });
        if (forestResults.length > 0 && forestResults[0]['msDS-Behavior-Version'] !== undefined) {
          forestFunctionalLevel = parseInt(forestResults[0]['msDS-Behavior-Version'], 10);
        }
      } catch (e) {
        // Forest level fetch failed, continue without it
      }

      // Check if AD Recycle Bin is enabled
      let recycleBinEnabled = false;
      try {
        const optionalFeaturesDN = `CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,${baseDN}`;
        const recycleBinResults = await this.ldapProvider.search<any>(optionalFeaturesDN, {
          filter: '(cn=Recycle Bin Feature)',
          attributes: ['msDS-EnabledFeatureBL'],
          scope: 'sub',
        });
        if (recycleBinResults.length > 0) {
          const enabledFeatureBL = recycleBinResults[0]['msDS-EnabledFeatureBL'];
          // If msDS-EnabledFeatureBL has entries, the feature is enabled for those partitions
          recycleBinEnabled = enabledFeatureBL && (Array.isArray(enabledFeatureBL) ? enabledFeatureBL.length > 0 : true);
        }
      } catch (e) {
        // Recycle Bin check failed, assume not enabled
      }

      return {
        dn: entry.dn,
        name: entry.name as string,
        domainFunctionalLevel,
        forestFunctionalLevel,
        recycleBinEnabled,
        ...entry,
      };
    } catch (error) {
      console.error('Failed to fetch domain:', error);
      return null;
    }
  }

  /**
   * Fetch GPO security settings from SYSVOL via SMB
   * Returns LDAP signing, channel binding, SMBv1, audit policy, PS logging settings
   */
  private async fetchGpoSecuritySettings(): Promise<GpoSecuritySettings | null> {
    // Check if SMB is enabled and we have config
    if (!this.smbConfig || !this.smbConfig.smb.enabled) {
      logger.debug('SMB is disabled, skipping GPO security settings fetch');
      return null;
    }

    const { smb, ldap } = this.smbConfig;
    const baseDN = this.ldapProvider.getBaseDN();
    const domainDnsName = this.extractDomainNameFromDN(baseDN);

    // Get DC hostname - we need a DC to read SYSVOL
    let dcHostname: string | null = null;
    try {
      const dcResults = await this.ldapProvider.search<any>(baseDN, {
        filter: '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
        attributes: ['dNSHostName'],
        scope: 'sub',
        sizeLimit: 1,
      });
      if (dcResults.length > 0 && dcResults[0].dNSHostName) {
        dcHostname = dcResults[0].dNSHostName;
      }
    } catch (e) {
      logger.debug('Failed to find DC for GPO settings fetch', { error: e });
    }

    if (!dcHostname) {
      // Try extracting from LDAP URL
      const urlMatch = ldap.url.match(/ldaps?:\/\/([^:/]+)/i);
      if (urlMatch && urlMatch[1]) {
        dcHostname = urlMatch[1];
      }
    }

    if (!dcHostname) {
      logger.debug('No DC hostname available for GPO settings fetch');
      return null;
    }

    // Use SMB credentials or fall back to LDAP credentials
    const username = smb.username || ldap.bindDN.split(',')[0]?.replace(/^CN=/i, '') || '';
    const password = smb.password || ldap.bindPassword;

    const baseDNMatch = ldap.baseDN.match(/DC=([^,]+)/i);
    const smbProviderConfig: SMBConfig = {
      host: dcHostname,
      share: 'SYSVOL',
      domain: baseDNMatch?.[1] || '',
      username,
      password,
      timeout: smb.timeout,
    };

    const smbProvider = new SMBProvider(smbProviderConfig);

    try {
      await smbProvider.connect();
      const settings = await smbProvider.readGpoSecuritySettings(domainDnsName);

      if (settings) {
        logger.debug('Successfully fetched GPO security settings from SYSVOL', {
          domainDnsName,
          hasLdapSigning: settings.ldapServerIntegrity !== undefined,
          hasAuditPolicy: settings.auditPolicies !== undefined,
          hasPsLogging: settings.powershellLogging !== undefined,
        });
      }

      return settings;
    } catch (error) {
      logger.warn('Failed to fetch GPO security settings via SMB', { error, dcHostname });
      return null;
    } finally {
      await smbProvider.disconnect();
    }
  }

  /**
   * Fetch OU count from AD
   */
  private async fetchOUCount(): Promise<number> {
    try {
      const baseDN = this.ldapProvider.getBaseDN();
      const filter = '(objectClass=organizationalUnit)';

      const results = await this.ldapProvider.search<any>(baseDN, {
        filter,
        attributes: ['dn'],
        scope: 'sub',
        paged: true,
      });

      return results.length;
    } catch (error) {
      logger.warn('Failed to fetch OU count', { error });
      return 0;
    }
  }

  /**
   * Fetch ACLs from sensitive AD objects
   *
   * Retrieves ntSecurityDescriptor from:
   * - All users, groups, computers (for delegation/privilege analysis)
   * - Critical system objects (AdminSDHolder, GPOs, Domain root)
   */
  private async fetchAcls(
    users: ADUser[],
    groups: ADGroup[],
    computers: ADComputer[]
  ): Promise<AclEntry[]> {
    const allAclEntries: AclEntry[] = [];
    const baseDN = this.ldapProvider.getBaseDN();

    try {
      resetParseStats(); // Reset stats at start

      // 1. Fetch ACLs for all users
      const userDns = users.map((u) => u.dn);
      const userAcls = await this.fetchAclsForObjects(userDns);
      // Use for loop to avoid stack overflow with large arrays
      for (const entry of userAcls) {
        allAclEntries.push(entry);
      }

      // 2. Fetch ACLs for all groups
      const groupDns = groups.map((g) => g.dn);
      const groupAcls = await this.fetchAclsForObjects(groupDns);
      // Use for loop to avoid stack overflow with large arrays
      for (const entry of groupAcls) {
        allAclEntries.push(entry);
      }

      // 3. Fetch ACLs for all computers
      const computerDns = computers.map((c) => c.dn);
      const computerAcls = await this.fetchAclsForObjects(computerDns);
      for (const entry of computerAcls) {
        allAclEntries.push(entry);
      }

      // 4. Fetch ACLs for critical system objects
      const systemObjects = [
        baseDN, // Domain root
        `CN=AdminSDHolder,CN=System,${baseDN}`,
        `CN=Policies,CN=System,${baseDN}`, // GPO container
      ];
      const systemAcls = await this.fetchAclsForObjects(systemObjects);
      for (const entry of systemAcls) {
        allAclEntries.push(entry);
      }

      return allAclEntries;
    } catch (error) {
      // Silently fail if permissions insufficient
      logger.warn('Failed to fetch ACL entries - insufficient permissions or unsupported configuration');
      return [];
    }
  }

  /**
   * Fetch ACLs for a list of object DNs
   */
  private async fetchAclsForObjects(objectDns: string[]): Promise<AclEntry[]> {
    const allAclEntries: AclEntry[] = [];
    let successCount = 0;

    // Batch requests to avoid overwhelming LDAP server
    const BATCH_SIZE = 100;
    for (let i = 0; i < objectDns.length; i += BATCH_SIZE) {
      const batch = objectDns.slice(i, i + BATCH_SIZE);

      // Query each object for its ntSecurityDescriptor
      const batchPromises = batch.map(async (dn) => {
        try {
          const results = await this.ldapProvider.search<any>(dn, {
            filter: '(objectClass=*)',
            attributes: ['nTSecurityDescriptor'], // Note: Capital T - that's the official AD schema name
            scope: 'base',
            controls: [createSDFlagsControl()], // Required to read security descriptors
          });

          if (results.length > 0 && results[0].nTSecurityDescriptor) {
            successCount++;
            const secDescriptor = results[0].nTSecurityDescriptor;

            // Convert to Buffer if needed (ldapts may return as Buffer or string)
            const buffer = Buffer.isBuffer(secDescriptor)
              ? secDescriptor
              : Buffer.from(secDescriptor, 'binary');
            const entries = parseSecurityDescriptor(buffer, dn);
            return entries;
          }
        } catch (error) {
          // Silently skip objects we can't read
          return [];
        }
        return [];
      });

      const batchResults = await Promise.all(batchPromises);
      batchResults.forEach((entries) => allAclEntries.push(...entries));
    }

    return allAclEntries;
  }

  /**
   * Fetch ADCS Certificate Templates from Configuration partition
   */
  private async fetchCertificateTemplates(): Promise<ADCSCertificateTemplate[]> {
    try {
      const baseDN = this.ldapProvider.getBaseDN();
      const templatesDN = `CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,${baseDN}`;

      const results = await this.ldapProvider.search<any>(templatesDN, {
        filter: '(objectClass=pKICertificateTemplate)',
        attributes: [
          'dn',
          'cn',
          'name',
          'displayName',
          'msPKI-Certificate-Name-Flag',
          'msPKI-Enrollment-Flag',
          'pKIExtendedKeyUsage',
          'nTSecurityDescriptor',
        ],
        scope: 'one',
        controls: [createSDFlagsControl()],
      });

      return results.map((entry: any) => ({
        dn: entry.dn,
        cn: entry.cn || entry.name,
        name: entry.name || entry.cn,
        displayName: entry.displayName,
        'msPKI-Certificate-Name-Flag': entry['msPKI-Certificate-Name-Flag']
          ? parseInt(entry['msPKI-Certificate-Name-Flag'], 10)
          : 0,
        'msPKI-Enrollment-Flag': entry['msPKI-Enrollment-Flag']
          ? parseInt(entry['msPKI-Enrollment-Flag'], 10)
          : 0,
        pKIExtendedKeyUsage: !entry.pKIExtendedKeyUsage
          ? []
          : Array.isArray(entry.pKIExtendedKeyUsage)
            ? entry.pKIExtendedKeyUsage
            : [entry.pKIExtendedKeyUsage],
        nTSecurityDescriptor: entry.nTSecurityDescriptor,
      }));
    } catch (error) {
      logger.debug('Could not fetch certificate templates (ADCS may not be configured)', { error });
      return [];
    }
  }

  /**
   * Fetch ADCS Certificate Authorities from Configuration partition
   */
  private async fetchCertificateAuthorities(): Promise<ADCSCertificateAuthority[]> {
    try {
      const baseDN = this.ldapProvider.getBaseDN();
      const enrollmentDN = `CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,${baseDN}`;

      const results = await this.ldapProvider.search<any>(enrollmentDN, {
        filter: '(objectClass=pKIEnrollmentService)',
        attributes: [
          'dn',
          'cn',
          'name',
          'dNSHostName',
          'certificateTemplates',
          'nTSecurityDescriptor',
        ],
        scope: 'one',
        controls: [createSDFlagsControl()],
      });

      return results.map((entry: any) => ({
        dn: entry.dn,
        cn: entry.cn || entry.name,
        name: entry.name || entry.cn,
        dNSHostName: entry.dNSHostName,
        certificateTemplates: !entry.certificateTemplates
          ? []
          : Array.isArray(entry.certificateTemplates)
            ? entry.certificateTemplates
            : [entry.certificateTemplates],
        nTSecurityDescriptor: entry.nTSecurityDescriptor,
      }));
    } catch (error) {
      logger.debug('Could not fetch certificate authorities (ADCS may not be configured)', { error });
      return [];
    }
  }

  /**
   * Fetch GPOs with ACLs and their links
   */
  private async fetchGPOsWithAcls(): Promise<{ gpos: ADGPO[]; links: GPOLink[]; gpoAcls: import('../../types/gpo.types').GPOAclEntry[] }> {
    const baseDN = this.ldapProvider.getBaseDN();
    const gpos: ADGPO[] = [];
    const links: GPOLink[] = [];
    const gpoAcls: import('../../types/gpo.types').GPOAclEntry[] = [];

    try {
      // 1. Fetch all GPOs
      const gpoResults = await this.ldapProvider.search<any>(`CN=Policies,CN=System,${baseDN}`, {
        filter: '(objectClass=groupPolicyContainer)',
        attributes: [
          'dn',
          'cn',
          'displayName',
          'gPCFileSysPath',
          'flags',
          'gPCMachineExtensionNames',
          'nTSecurityDescriptor',
        ],
        scope: 'one',
        controls: [createSDFlagsControl()],
      });

      for (const entry of gpoResults) {
        const flags = entry.flags ? parseInt(entry.flags, 10) : 0;
        gpos.push({
          dn: entry.dn,
          cn: entry.cn,
          displayName: entry.displayName,
          gPCFileSysPath: entry.gPCFileSysPath,
          flags,
          gPCMachineExtensionNames: entry.gPCMachineExtensionNames,
          nTSecurityDescriptor: entry.nTSecurityDescriptor,
        });

        // Parse GPO security descriptor to extract ACLs
        if (entry.nTSecurityDescriptor) {
          try {
            const buffer = Buffer.isBuffer(entry.nTSecurityDescriptor)
              ? entry.nTSecurityDescriptor
              : Buffer.from(entry.nTSecurityDescriptor, 'binary');
            const aclEntries = parseSecurityDescriptor(buffer, entry.dn);
            for (const acl of aclEntries) {
              gpoAcls.push({
                gpoDn: entry.dn,
                gpoName: entry.displayName || entry.cn,
                trustee: acl.trustee,
                trusteeSid: acl.trustee, // trustee is already the SID
                accessMask: acl.accessMask,
                aceType: typeof acl.aceType === 'string' ? parseInt(acl.aceType, 10) : acl.aceType,
              });
            }
          } catch (e) {
            // Skip GPOs we can't parse ACLs for
            logger.debug('Could not parse GPO ACLs for', { gpo: entry.displayName, error: e });
          }
        }
      }

      // 2. Fetch GPO links from OUs, domain, and sites
      const linkResults = await this.ldapProvider.search<any>(baseDN, {
        filter: '(gPLink=*)',
        attributes: ['dn', 'gPLink'],
        scope: 'sub',
        sizeLimit: 1000,
      });

      for (const entry of linkResults) {
        const gpLink = entry.gPLink;
        if (!gpLink) continue;

        // Parse gPLink format: [LDAP://cn={GUID},...;options][...]
        const linkMatches = gpLink.matchAll(/\[LDAP:\/\/([^\]]+);(\d+)\]/gi);
        for (const match of linkMatches) {
          const gpoDn = match[1];
          const options = parseInt(match[2], 10);

          // Extract GUID from DN
          const guidMatch = gpoDn.match(/cn=(\{[^}]+\})/i);
          if (guidMatch) {
            links.push({
              gpoGuid: guidMatch[1],
              linkedTo: entry.dn,
              enforced: (options & 2) !== 0, // GPO_FLAG_ENFORCED
              disabled: (options & 1) !== 0, // GPO_FLAG_DISABLED
            });
          }
        }
      }
    } catch (error) {
      logger.debug('Could not fetch GPOs with ACLs', { error });
    }

    return { gpos, links, gpoAcls };
  }

  /**
   * Fetch extended trust information with security attributes
   */
  private async fetchTrustsExtended(): Promise<ADTrustExtended[]> {
    try {
      const baseDN = this.ldapProvider.getBaseDN();

      const results = await this.ldapProvider.search<any>(`CN=System,${baseDN}`, {
        filter: '(objectClass=trustedDomain)',
        attributes: [
          'dn',
          'name',
          'trustDirection',
          'trustType',
          'trustAttributes',
          'flatName',
          'securityIdentifier',
        ],
        scope: 'one',
      });

      return results.map((entry: any) => {
        const trustDirection = parseInt(entry.trustDirection || '0', 10);
        const trustType = parseInt(entry.trustType || '0', 10);
        const trustAttributes = parseInt(entry.trustAttributes || '0', 10);

        // Parse and enrich trust data
        const parsed = parseTrustAttributes(trustAttributes);

        return {
          dn: entry.dn,
          name: entry.name,
          flatName: entry.flatName,
          trustDirection,
          trustType,
          trustAttributes,
          direction: parseTrustDirection(trustDirection),
          type: parseTrustType(trustType, trustAttributes),
          ...parsed, // sidFilteringEnabled, selectiveAuthEnabled, isTransitive
        };
      });
    } catch (error) {
      logger.debug('Could not fetch extended trust information', { error });
      return [];
    }
  }

  /**
   * Fetch domain configuration (password policy, domain info, trusts, GPOs)
   */
  private async fetchDomainConfig(domain: ADDomain | null): Promise<DomainConfig> {
    const baseDN = this.ldapProvider.getBaseDN();

    // Default config
    const config: DomainConfig = {
      passwordPolicy: {
        minPasswordLength: 0,
        passwordHistoryLength: 0,
        maxPasswordAge: 'Not configured',
        minPasswordAge: 'Not configured',
        lockoutThreshold: 0,
        lockoutDuration: 'Not configured',
        lockoutObservationWindow: 'Not configured',
        complexity: false,
      },
      kerberosPolicy: getDefaultKerberosPolicy(),
      domainInfo: {
        forestName: '',
        domainName: '',
        domainMode: 'Unknown',
        forestMode: 'Unknown',
        domainControllers: [],
        fsmoRoles: {},
      },
      trusts: [],
      gpoSummary: {
        totalGPOs: 0,
        linkedGPOs: 0,
      },
    };

    try {
      // 1. Fetch password policy from domain
      const policyResults = await this.ldapProvider.search<any>(baseDN, {
        filter: '(objectClass=domain)',
        attributes: [
          'minPwdLength',
          'pwdHistoryLength',
          'maxPwdAge',
          'minPwdAge',
          'lockoutThreshold',
          'lockoutDuration',
          'lockOutObservationWindow',
          'pwdProperties',
          'name',
        ],
        scope: 'base',
      });

      if (policyResults.length > 0) {
        const policy = policyResults[0];
        config.passwordPolicy.minPasswordLength = parseInt(policy.minPwdLength || '0', 10);
        config.passwordPolicy.passwordHistoryLength = parseInt(policy.pwdHistoryLength || '0', 10);
        config.passwordPolicy.maxPasswordAge = this.formatFiletimeDuration(policy.maxPwdAge);
        config.passwordPolicy.minPasswordAge = this.formatFiletimeDuration(policy.minPwdAge);
        config.passwordPolicy.lockoutThreshold = parseInt(policy.lockoutThreshold || '0', 10);
        config.passwordPolicy.lockoutDuration = this.formatFiletimeDuration(policy.lockoutDuration);
        config.passwordPolicy.lockoutObservationWindow = this.formatFiletimeDuration(
          policy.lockOutObservationWindow
        );
        // pwdProperties bit 1 = DOMAIN_PASSWORD_COMPLEX
        config.passwordPolicy.complexity = (parseInt(policy.pwdProperties || '0', 10) & 1) === 1;
        config.domainInfo.domainName = policy.name || '';
      }

      // 2. Fetch domain functional levels
      if (domain) {
        config.domainInfo.domainMode = this.getDomainModeName(domain.domainFunctionalLevel);
        config.domainInfo.forestMode = this.getDomainModeName(domain.forestFunctionalLevel);
        config.domainInfo.forestName = this.extractDomainNameFromDN(baseDN);
        config.domainInfo.domainName = this.extractDomainNameFromDN(baseDN);
      }

      // 3. Fetch domain controllers
      const dcResults = await this.ldapProvider.search<any>(baseDN, {
        filter: '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
        attributes: ['dNSHostName', 'name'],
        scope: 'sub',
      });

      config.domainInfo.domainControllers = dcResults
        .map((dc: any) => dc.dNSHostName || dc.name)
        .filter((name: string) => name);

      // 4. Fetch FSMO role holders
      await this.fetchFSMORoles(config, baseDN);

      // 5. Fetch trust relationships
      await this.fetchTrusts(config, baseDN);

      // 6. Fetch GPO count
      await this.fetchGPOCount(config, baseDN);

      // 7. Fetch Kerberos policy via SMB (or use defaults)
      const dcHostname = config.domainInfo.domainControllers[0];
      if (dcHostname) {
        const domainDnsName = this.extractDomainNameFromDN(baseDN);
        config.kerberosPolicy = await this.fetchKerberosPolicyViaSMB(domainDnsName, dcHostname);
      } else {
        // No DC found, use defaults
        config.kerberosPolicy = getDefaultKerberosPolicy();
      }
    } catch (error) {
      logger.warn('Failed to fetch some domain configuration', { error });
    }

    return config;
  }

  /**
   * Format Windows FILETIME duration to human-readable string
   * FILETIME durations are negative 100-nanosecond intervals
   */
  private formatFiletimeDuration(filetime: any): string {
    if (!filetime) return 'Not configured';

    const value = typeof filetime === 'string' ? parseInt(filetime, 10) : filetime;
    if (value === 0 || isNaN(value)) return 'Not configured';

    // Convert from negative 100-ns intervals to positive minutes
    const minutes = Math.abs(value) / (10000000 * 60);

    if (minutes < 60) {
      return `${Math.round(minutes)} min`;
    } else if (minutes < 1440) {
      const hours = Math.round(minutes / 60);
      return `${hours} hour${hours > 1 ? 's' : ''}`;
    } else {
      const days = Math.round(minutes / 1440);
      return `${days} day${days > 1 ? 's' : ''}`;
    }
  }

  /**
   * Get human-readable domain functional level name
   */
  private getDomainModeName(level: number | undefined): string {
    if (level === undefined) return 'Unknown';

    const levels: Record<number, string> = {
      0: 'Windows2000Domain',
      1: 'Windows2003InterimDomain',
      2: 'Windows2003Domain',
      3: 'Windows2008Domain',
      4: 'Windows2008R2Domain',
      5: 'Windows2012Domain',
      6: 'Windows2012R2Domain',
      7: 'Windows2016Domain',
    };

    return levels[level] || `Unknown (${level})`;
  }

  /**
   * Extract domain name from DN
   */
  private extractDomainNameFromDN(dn: string): string {
    const parts = dn.match(/DC=([^,]+)/gi);
    if (!parts) return dn;
    return parts.map((p) => p.replace(/DC=/i, '')).join('.');
  }

  /**
   * Fetch FSMO role holders
   */
  private async fetchFSMORoles(config: DomainConfig, baseDN: string): Promise<void> {
    try {
      // PDC Emulator, RID Master, Infrastructure Master are on domain
      const domainRoles = await this.ldapProvider.search<any>(baseDN, {
        filter: '(objectClass=domain)',
        attributes: ['fSMORoleOwner'],
        scope: 'base',
      });

      if (domainRoles.length > 0 && domainRoles[0].fSMORoleOwner) {
        config.domainInfo.fsmoRoles.pdcEmulator = this.extractServerFromDN(domainRoles[0].fSMORoleOwner);
      }

      // RID Master
      const ridResults = await this.ldapProvider.search<any>(`CN=RID Manager$,CN=System,${baseDN}`, {
        filter: '(objectClass=*)',
        attributes: ['fSMORoleOwner'],
        scope: 'base',
      });

      if (ridResults.length > 0 && ridResults[0].fSMORoleOwner) {
        config.domainInfo.fsmoRoles.ridMaster = this.extractServerFromDN(ridResults[0].fSMORoleOwner);
      }

      // Infrastructure Master
      const infraResults = await this.ldapProvider.search<any>(
        `CN=Infrastructure,${baseDN}`,
        {
          filter: '(objectClass=*)',
          attributes: ['fSMORoleOwner'],
          scope: 'base',
        }
      );

      if (infraResults.length > 0 && infraResults[0].fSMORoleOwner) {
        config.domainInfo.fsmoRoles.infrastructureMaster = this.extractServerFromDN(
          infraResults[0].fSMORoleOwner
        );
      }
    } catch (error) {
      logger.debug('Could not fetch all FSMO roles', { error });
    }
  }

  /**
   * Extract server name from FSMO role owner DN
   */
  private extractServerFromDN(dn: string): string {
    // DN format: CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,...
    const match = dn.match(/CN=NTDS Settings,CN=([^,]+)/i);
    return match && match[1] ? match[1] : dn;
  }

  /**
   * Fetch trust relationships
   */
  private async fetchTrusts(config: DomainConfig, baseDN: string): Promise<void> {
    try {
      const trustResults = await this.ldapProvider.search<any>(`CN=System,${baseDN}`, {
        filter: '(objectClass=trustedDomain)',
        attributes: ['name', 'trustDirection', 'trustType', 'trustAttributes'],
        scope: 'one',
      });

      config.trusts = trustResults.map((trust: any) => {
        const direction = parseInt(trust.trustDirection || '0', 10);
        const trustType = parseInt(trust.trustType || '0', 10);
        const attributes = parseInt(trust.trustAttributes || '0', 10);

        return {
          name: trust.name || 'Unknown',
          direction: this.getTrustDirection(direction),
          type: this.getTrustType(trustType),
          transitive: (attributes & 1) === 1, // TRUST_ATTRIBUTE_NON_TRANSITIVE = 0x1 (inverted)
        };
      });
    } catch (error) {
      logger.debug('Could not fetch trust relationships', { error });
    }
  }

  /**
   * Get trust direction name
   */
  private getTrustDirection(direction: number): 'inbound' | 'outbound' | 'bidirectional' {
    switch (direction) {
      case 1:
        return 'inbound';
      case 2:
        return 'outbound';
      case 3:
        return 'bidirectional';
      default:
        return 'inbound';
    }
  }

  /**
   * Get trust type name
   */
  private getTrustType(type: number): 'forest' | 'external' | 'realm' | 'shortcut' {
    switch (type) {
      case 1:
        return 'external'; // TRUST_TYPE_DOWNLEVEL
      case 2:
        return 'external'; // TRUST_TYPE_UPLEVEL (AD domain)
      case 3:
        return 'realm'; // TRUST_TYPE_MIT (Kerberos realm)
      case 4:
        return 'external'; // TRUST_TYPE_DCE
      default:
        return 'external';
    }
  }

  /**
   * Fetch GPO count
   */
  private async fetchGPOCount(config: DomainConfig, baseDN: string): Promise<void> {
    try {
      const gpoResults = await this.ldapProvider.search<any>(`CN=Policies,CN=System,${baseDN}`, {
        filter: '(objectClass=groupPolicyContainer)',
        attributes: ['cn', 'gPCFileSysPath'],
        scope: 'one',
      });

      config.gpoSummary.totalGPOs = gpoResults.length;

      // Count linked GPOs by searching for gPLink attributes
      const linkedResults = await this.ldapProvider.search<any>(baseDN, {
        filter: '(gPLink=*)',
        attributes: ['gPLink'],
        scope: 'sub',
        sizeLimit: 1000,
      });

      // Count unique GPO links
      const linkedGPOs = new Set<string>();
      linkedResults.forEach((obj: any) => {
        const gpLink = obj.gPLink;
        if (gpLink) {
          // gPLink format: [LDAP://cn={GUID},cn=policies,cn=system,DC=domain,DC=com;0]
          const matches = gpLink.match(/cn=\{[^}]+\}/gi);
          if (matches) {
            matches.forEach((m: string) => linkedGPOs.add(m.toLowerCase()));
          }
        }
      });

      config.gpoSummary.linkedGPOs = linkedGPOs.size;
    } catch (error) {
      logger.debug('Could not fetch GPO count', { error });
    }
  }

  /**
   * Fetch Kerberos policy from SYSVOL via SMB
   * Returns formatted policy with isDefault flag
   * Returns default Windows values if file not found or SMB disabled
   */
  private async fetchKerberosPolicyViaSMB(domainDnsName: string, dcHostname: string): Promise<FormattedKerberosPolicy> {
    // Check if SMB is enabled and we have config
    if (!this.smbConfig || !this.smbConfig.smb.enabled) {
      logger.debug('SMB is disabled, returning default Kerberos policy values');
      return getDefaultKerberosPolicy();
    }

    const { smb, ldap } = this.smbConfig!;

    // Use SMB credentials or fall back to LDAP credentials
    const username = smb.username || ldap.bindDN.split(',')[0]?.replace(/^CN=/i, '') || '';
    const password = smb.password || ldap.bindPassword;

    const baseDNMatch = ldap.baseDN.match(/DC=([^,]+)/i);
    const smbProviderConfig: SMBConfig = {
      host: dcHostname,
      share: 'SYSVOL',
      domain: baseDNMatch?.[1] || '',
      username,
      password,
      timeout: smb.timeout,
    };

    const smbProvider = new SMBProvider(smbProviderConfig);

    try {
      await smbProvider.connect();
      const kerberosPolicy = await smbProvider.readKerberosPolicy(domainDnsName);

      if (kerberosPolicy) {
        logger.debug('Successfully fetched Kerberos policy from SYSVOL', { domainDnsName });
        return formatKerberosPolicy(kerberosPolicy, false);
      }

      // File not found - return Windows defaults
      logger.debug('GptTmpl.inf not found, using Windows default Kerberos policy values');
      return getDefaultKerberosPolicy();
    } catch (error) {
      logger.warn('Failed to fetch Kerberos policy via SMB, using defaults', { error, dcHostname });
      return getDefaultKerberosPolicy();
    } finally {
      await smbProvider.disconnect();
    }
  }
}
