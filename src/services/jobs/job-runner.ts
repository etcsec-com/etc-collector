/**
 * Job Runner
 *
 * Executes AD audits asynchronously with step-by-step progress tracking.
 * Each step reports progress to JobStore for polling clients.
 */

import { LDAPProvider } from '../../providers/ldap/ldap.provider';
import { ADUser, ADGroup, ADComputer, ADDomain, AclEntry } from '../../types/ad.types';
import { LDAPControl } from '../../providers/interfaces/ILDAPProvider';
import { parseSecurityDescriptor, resetParseStats } from '../../providers/ldap/acl-parser';
import { Finding } from '../../types/finding.types';
import { calculateSecurityScore, SecurityScore } from '../audit/scoring.service';
import { DomainConfig } from '../audit/response-formatter';
import { logger } from '../../utils/logger';
import { JobStore } from './job-store';
import { AuditStepName, Job, JobType } from './job.types';
import { SMBProvider, formatKerberosPolicy, getDefaultKerberosPolicy, SMBConfig, FormattedKerberosPolicy } from '../../providers/smb/smb.provider';
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
} from '../audit/detectors/ad';

// Import new types for ADCS, GPO, Trusts
import { ADCSCertificateTemplate, ADCSCertificateAuthority } from '../../types/adcs.types';
import { ADGPO, GPOLink } from '../../types/gpo.types';
import { ADTrustExtended, parseTrustAttributes, parseTrustDirection, parseTrustType } from '../../types/trust.types';
import { computeAttackGraph } from '../audit/attack-graph.service';
import { AttackGraphExport } from '../../types/attack-graph.types';

/**
 * Create LDAP_SERVER_SD_FLAGS_OID control for reading Security Descriptors
 */
function createSDFlagsControl(): LDAPControl {
  const LDAP_SERVER_SD_FLAGS_OID = '1.2.840.113556.1.4.801';
  const SD_FLAGS = 0x00000007;
  const buffer = Buffer.from([0x02, 0x01, SD_FLAGS]);
  return {
    oid: LDAP_SERVER_SD_FLAGS_OID,
    critical: false,
    value: buffer,
  };
}

/**
 * Convert Windows FILETIME to JavaScript Date
 */
function convertFiletimeToDate(filetime: any): Date | undefined {
  if (!filetime) return undefined;

  let filetimeNum: number;
  if (typeof filetime === 'string') {
    filetimeNum = parseInt(filetime, 10);
  } else if (typeof filetime === 'number') {
    filetimeNum = filetime;
  } else {
    return undefined;
  }

  if (filetimeNum === 0 || filetimeNum >= 9223372036854775807) {
    return undefined;
  }

  const milliseconds = filetimeNum / 10000;
  const epochOffset = 11644473600000;
  const unixTimestamp = milliseconds - epochOffset;

  if (unixTimestamp < 0 || unixTimestamp > Date.now() + 100 * 365 * 24 * 60 * 60 * 1000) {
    return undefined;
  }

  return new Date(unixTimestamp);
}

/**
 * Audit options for job runner
 */
export interface JobRunnerOptions {
  includeDetails?: boolean;
  maxUsers?: number;
  maxGroups?: number;
  maxComputers?: number;
}

/**
 * Audit result with all findings
 */
export interface AuditResult {
  score: SecurityScore;
  findings: Finding[];
  stats: {
    totalUsers: number;
    enabledUsers: number;
    disabledUsers: number;
    totalGroups: number;
    totalComputers: number;
    totalOUs: number;
    totalFindings: number;
    executionTimeMs: number;
  };
  timestamp: Date;
  domainConfig?: DomainConfig;
  attackGraph?: AttackGraphExport;
}

/**
 * Job Runner - Executes AD audits with progress tracking
 */
export class JobRunner {
  private jobStore: JobStore;
  private ldapProvider: LDAPProvider;
  private smbConfig?: { smb: AppSMBConfig; ldap: LDAPConfig };

  constructor(ldapProvider: LDAPProvider, smbConfig?: { smb: AppSMBConfig; ldap: LDAPConfig }) {
    this.jobStore = JobStore.getInstance();
    this.ldapProvider = ldapProvider;
    this.smbConfig = smbConfig;
  }

  /**
   * Start an async AD audit job
   * Returns immediately with job ID, audit runs in background
   */
  startAudit(options: JobRunnerOptions = {}): Job {
    const job = this.jobStore.createJob({
      type: 'ad-audit' as JobType,
      options: options as Record<string, unknown>,
    });

    // Start audit in background (don't await)
    this.runAuditAsync(job.job_id, options).catch((error) => {
      logger.error('Async audit failed', { job_id: job.job_id, error });
    });

    return job;
  }

  /**
   * Run the audit asynchronously with step progress updates
   */
  private async runAuditAsync(jobId: string, options: JobRunnerOptions): Promise<void> {
    const startTime = Date.now();
    const { includeDetails = false, maxUsers, maxGroups, maxComputers } = options;

    try {
      // Mark job as running
      this.jobStore.startJob(jobId);

      // ===== STEP 1: CONNECTING =====
      this.jobStore.startStep(jobId, 'CONNECTING', 'Connecting to LDAP server');
      const connectionTest = await this.ldapProvider.testConnection();
      if (!connectionTest.success) {
        throw new Error(`LDAP connection failed: ${connectionTest.message}`);
      }
      this.jobStore.completeStep(jobId, 'CONNECTING');

      // ===== STEP 2: FETCHING_USERS =====
      this.jobStore.startStep(jobId, 'FETCHING_USERS', 'Fetching users from Active Directory');
      const users = await this.fetchUsers(maxUsers);
      this.jobStore.completeStep(jobId, 'FETCHING_USERS', { count: users.length });

      // ===== STEP 3: FETCHING_GROUPS =====
      this.jobStore.startStep(jobId, 'FETCHING_GROUPS', 'Fetching groups from Active Directory');
      const groups = await this.fetchGroups(maxGroups);
      this.jobStore.completeStep(jobId, 'FETCHING_GROUPS', { count: groups.length });

      // ===== STEP 4: FETCHING_COMPUTERS =====
      this.jobStore.startStep(jobId, 'FETCHING_COMPUTERS', 'Fetching computers from Active Directory');
      const computers = await this.fetchComputers(maxComputers);
      this.jobStore.completeStep(jobId, 'FETCHING_COMPUTERS', { count: computers.length });

      // ===== STEP 5: FETCHING_DOMAIN =====
      this.jobStore.startStep(jobId, 'FETCHING_DOMAIN', 'Fetching domain information and OUs');
      const [domain, ouCount] = await Promise.all([
        this.fetchDomain(),
        this.fetchOUCount(),
      ]);
      this.jobStore.completeStep(jobId, 'FETCHING_DOMAIN', { count: ouCount });

      // ===== STEP 6: FETCHING_ACLS =====
      this.jobStore.startStep(jobId, 'FETCHING_ACLS', 'Fetching security descriptors (ACLs)');
      const aclEntries = await this.fetchAcls(users, groups, computers, jobId);
      this.jobStore.completeStep(jobId, 'FETCHING_ACLS', { count: aclEntries.length });

      // ===== STEP 6.5: FETCHING ADCS/GPO/TRUSTS =====
      // Fetch certificate templates, CAs, GPOs, and extended trusts in parallel
      const [certTemplates, certAuthorities, gpoData, trustsExtended] = await Promise.all([
        this.fetchCertificateTemplates(),
        this.fetchCertificateAuthorities(),
        this.fetchGPOsWithAcls(),
        this.fetchTrustsExtended(),
      ]);

      // Data for advanced detectors
      const templates: any[] = certTemplates;
      const cas: any[] = certAuthorities;
      const fsps: any[] = [];

      // All findings
      const findings: Finding[] = [];

      // ===== STEP 7: DETECTING_PASSWORDS =====
      this.jobStore.startStep(jobId, 'DETECTING_PASSWORDS', 'Analyzing password vulnerabilities (7 checks)');
      const passwordFindings = detectPasswordVulnerabilities(users, includeDetails);
      findings.push(...passwordFindings);
      this.jobStore.completeStep(jobId, 'DETECTING_PASSWORDS', { findings: passwordFindings.length });

      // ===== STEP 8: DETECTING_KERBEROS =====
      this.jobStore.startStep(jobId, 'DETECTING_KERBEROS', 'Analyzing Kerberos vulnerabilities (8 checks)');
      const kerberosFindings = detectKerberosVulnerabilities(users, includeDetails);
      findings.push(...kerberosFindings);
      this.jobStore.completeStep(jobId, 'DETECTING_KERBEROS', { findings: kerberosFindings.length });

      // ===== STEP 9: DETECTING_ACCOUNTS =====
      this.jobStore.startStep(jobId, 'DETECTING_ACCOUNTS', 'Analyzing account vulnerabilities (15 checks)');
      const accountsFindings = detectAccountsVulnerabilities(users, includeDetails);
      findings.push(...accountsFindings);
      this.jobStore.completeStep(jobId, 'DETECTING_ACCOUNTS', { findings: accountsFindings.length });

      // ===== STEP 10: DETECTING_GROUPS =====
      this.jobStore.startStep(jobId, 'DETECTING_GROUPS', 'Analyzing group vulnerabilities (7 checks)');
      const groupsFindings = detectGroupsVulnerabilities(users, groups, includeDetails);
      findings.push(...groupsFindings);
      this.jobStore.completeStep(jobId, 'DETECTING_GROUPS', { findings: groupsFindings.length });

      // ===== STEP 11: DETECTING_COMPUTERS =====
      this.jobStore.startStep(jobId, 'DETECTING_COMPUTERS', 'Analyzing computer vulnerabilities (17 checks)');
      const computersFindings = detectComputersVulnerabilities(computers, includeDetails);
      findings.push(...computersFindings);
      this.jobStore.completeStep(jobId, 'DETECTING_COMPUTERS', { findings: computersFindings.length });

      // ===== STEP 12: DETECTING_ADVANCED =====
      this.jobStore.startStep(jobId, 'DETECTING_ADVANCED', 'Analyzing advanced vulnerabilities (22 checks)');
      const advancedFindings = detectAdvancedVulnerabilities(
        users,
        computers,
        domain,
        templates,
        cas,
        fsps,
        includeDetails
      );
      findings.push(...advancedFindings);
      this.jobStore.completeStep(jobId, 'DETECTING_ADVANCED', { findings: advancedFindings.length });

      // ===== STEP 13: DETECTING_PERMISSIONS =====
      this.jobStore.startStep(jobId, 'DETECTING_PERMISSIONS', 'Analyzing permission vulnerabilities (9 checks)');
      const permissionsFindings = detectPermissionsVulnerabilities(aclEntries, includeDetails);
      findings.push(...permissionsFindings);
      this.jobStore.completeStep(jobId, 'DETECTING_PERMISSIONS', { findings: permissionsFindings.length });

      // ===== STEP 13.5: DETECTING_ADCS =====
      this.jobStore.startStep(jobId, 'DETECTING_ADCS' as AuditStepName, 'Analyzing ADCS vulnerabilities (ESC1-ESC8)');
      const adcsFindings = detectAdcsVulnerabilities(certTemplates, certAuthorities, includeDetails);
      findings.push(...adcsFindings);
      this.jobStore.completeStep(jobId, 'DETECTING_ADCS' as AuditStepName, { findings: adcsFindings.length });

      // ===== STEP 13.6: DETECTING_GPO =====
      this.jobStore.startStep(jobId, 'DETECTING_GPO' as AuditStepName, 'Analyzing GPO security (5 checks)');
      const gpoFindings = detectGpoVulnerabilities(
        gpoData.gpos,
        gpoData.links,
        domain ? { minPasswordLength: domain['minPwdLength'] as number | undefined } : null,
        includeDetails
      );
      findings.push(...gpoFindings);
      this.jobStore.completeStep(jobId, 'DETECTING_GPO' as AuditStepName, { findings: gpoFindings.length });

      // ===== STEP 13.7: DETECTING_TRUSTS =====
      this.jobStore.startStep(jobId, 'DETECTING_TRUSTS' as AuditStepName, 'Analyzing trust relationships (4 checks)');
      const trustsFindings = detectTrustVulnerabilities(trustsExtended, includeDetails);
      findings.push(...trustsFindings);
      this.jobStore.completeStep(jobId, 'DETECTING_TRUSTS' as AuditStepName, { findings: trustsFindings.length });

      // ===== STEP 13.8: DETECTING_ATTACK_PATHS =====
      this.jobStore.startStep(jobId, 'DETECTING_ATTACK_PATHS' as AuditStepName, 'Analyzing attack paths (11 checks)');
      const attackPathFindings = detectAttackPathVulnerabilities(
        users,
        groups,
        computers,
        aclEntries,
        gpoData.gpos,
        trustsExtended,
        certTemplates,
        includeDetails
      );
      findings.push(...attackPathFindings);
      this.jobStore.completeStep(jobId, 'DETECTING_ATTACK_PATHS' as AuditStepName, { findings: attackPathFindings.length });

      // ===== STEP 13.9: DETECTING_MONITORING =====
      this.jobStore.startStep(jobId, 'DETECTING_MONITORING' as AuditStepName, 'Analyzing monitoring configuration (6 checks)');
      const monitoringFindings = detectMonitoringVulnerabilities(users, groups, domain, includeDetails);
      findings.push(...monitoringFindings);
      this.jobStore.completeStep(jobId, 'DETECTING_MONITORING' as AuditStepName, { findings: monitoringFindings.length });

      // ===== STEP 14: CALCULATING_SCORE =====
      this.jobStore.startStep(jobId, 'CALCULATING_SCORE', 'Calculating security score');
      const score = calculateSecurityScore(findings, users.length);
      this.jobStore.completeStep(jobId, 'CALCULATING_SCORE');

      // ===== STEP 15: FETCHING_CONFIG =====
      this.jobStore.startStep(jobId, 'FETCHING_CONFIG', 'Fetching domain configuration');
      const domainConfig = await this.fetchDomainConfig(domain);
      this.jobStore.completeStep(jobId, 'FETCHING_CONFIG');

      // ===== STEP 15.5: COMPUTING_ATTACK_GRAPH =====
      this.jobStore.startStep(jobId, 'COMPUTING_ATTACK_GRAPH' as AuditStepName, 'Computing attack paths graph');
      const baseDN = this.ldapProvider.getBaseDN();
      const attackGraph = computeAttackGraph(
        users,
        groups,
        computers,
        aclEntries,
        certTemplates,
        gpoData.gpos,
        {
          name: domainConfig?.domainInfo?.domainName || this.extractDomainNameFromDN(baseDN),
          sid: undefined,
        },
        500
      );
      this.jobStore.completeStep(jobId, 'COMPUTING_ATTACK_GRAPH' as AuditStepName, {
        count: attackGraph.paths.length,
      });

      // ===== STEP 16: FORMATTING =====
      this.jobStore.startStep(jobId, 'FORMATTING', 'Formatting audit response');
      const executionTimeMs = Date.now() - startTime;

      // Calculate enabled/disabled user counts (UAC flag 0x2 = ACCOUNTDISABLE)
      const disabledUsers = users.filter((u) => ((u.userAccountControl ?? 0) & 0x2) !== 0).length;
      const enabledUsers = users.length - disabledUsers;

      const result: AuditResult = {
        score,
        findings,
        stats: {
          totalUsers: users.length,
          enabledUsers,
          disabledUsers,
          totalGroups: groups.length,
          totalComputers: computers.length,
          totalOUs: ouCount,
          totalFindings: findings.length,
          executionTimeMs,
        },
        timestamp: new Date(),
        domainConfig,
        attackGraph,
      };
      this.jobStore.completeStep(jobId, 'FORMATTING');

      // Complete job with result
      this.jobStore.completeJob(jobId, result);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      const currentStep = this.jobStore.getJob(jobId)?.current_step || 'CONNECTING';

      this.jobStore.failStep(jobId, currentStep as AuditStepName, errorMessage);
      this.jobStore.failJob(jobId, {
        code: 'AUDIT_FAILED',
        message: errorMessage,
        step: currentStep as AuditStepName,
      });
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
    ];

    const results = await this.ldapProvider.search<any>(baseDN, {
      filter,
      attributes,
      scope: 'sub',
      sizeLimit: maxUsers,
      paged: true,
    });

    return results.map((entry: any) => ({
      ...entry,
      dn: entry.dn,
      sAMAccountName: entry.sAMAccountName as string,
      userPrincipalName: entry.userPrincipalName as string,
      displayName: entry.displayName as string,
      enabled: !((entry.userAccountControl as number) & 0x2),
      passwordLastSet: convertFiletimeToDate(entry.passwordLastSet),
      lastLogon: convertFiletimeToDate(entry.lastLogon),
      accountExpires: convertFiletimeToDate(entry.accountExpires),
      adminCount: entry.adminCount as number,
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
      paged: true,
    });

    return results.map((entry: any) => ({
      ...entry,
      dn: entry.dn,
      sAMAccountName: entry.sAMAccountName as string,
      displayName: entry.displayName as string,
      groupType: entry.groupType as number,
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
      'msLAPS-Password',
      'msDS-AllowedToDelegateTo',
      'msDS-AllowedToActOnBehalfOfOtherIdentity',
      'msDS-SupportedEncryptionTypes',
      'memberOf',
      'description',
      'whenChanged',
      'adminCount',
    ];

    const results = await this.ldapProvider.search<any>(baseDN, {
      filter,
      attributes,
      scope: 'sub',
      sizeLimit: maxComputers,
      paged: true,
    });

    return results.map((entry: any) => ({
      ...entry,
      dn: entry.dn,
      sAMAccountName: entry.sAMAccountName as string,
      dNSHostName: entry.dNSHostName as string,
      operatingSystem: entry.operatingSystem as string,
      operatingSystemVersion: entry.operatingSystemVersion as string,
      lastLogon: convertFiletimeToDate(entry.lastLogon),
      pwdLastSet: convertFiletimeToDate(entry.pwdLastSet),
      enabled: !((entry.userAccountControl as number) & 0x2),
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

      return {
        dn: entry.dn,
        name: entry.name as string,
        domainFunctionalLevel,
        forestFunctionalLevel,
        ...entry,
      };
    } catch (error) {
      logger.error('Failed to fetch domain:', error);
      return null;
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
   * Fetch ACLs from sensitive AD objects with progress updates
   */
  private async fetchAcls(
    users: ADUser[],
    groups: ADGroup[],
    computers: ADComputer[],
    jobId: string
  ): Promise<AclEntry[]> {
    const allAclEntries: AclEntry[] = [];
    const baseDN = this.ldapProvider.getBaseDN();

    try {
      resetParseStats();

      const totalObjects = users.length + groups.length + computers.length + 3; // +3 for system objects
      let processed = 0;

      // 1. Fetch ACLs for all users
      const userDns = users.map((u) => u.dn);
      const userAcls = await this.fetchAclsForObjects(userDns, (count) => {
        processed += count;
        this.jobStore.updateStepProgress(jobId, 'FETCHING_ACLS', {
          progress: Math.round((processed / totalObjects) * 100),
          description: `Fetching ACLs: ${processed}/${totalObjects} objects`,
        });
      });
      for (const entry of userAcls) {
        allAclEntries.push(entry);
      }

      // 2. Fetch ACLs for all groups
      const groupDns = groups.map((g) => g.dn);
      const groupAcls = await this.fetchAclsForObjects(groupDns, (count) => {
        processed += count;
        this.jobStore.updateStepProgress(jobId, 'FETCHING_ACLS', {
          progress: Math.round((processed / totalObjects) * 100),
          description: `Fetching ACLs: ${processed}/${totalObjects} objects`,
        });
      });
      for (const entry of groupAcls) {
        allAclEntries.push(entry);
      }

      // 3. Fetch ACLs for all computers
      const computerDns = computers.map((c) => c.dn);
      const computerAcls = await this.fetchAclsForObjects(computerDns, (count) => {
        processed += count;
        this.jobStore.updateStepProgress(jobId, 'FETCHING_ACLS', {
          progress: Math.round((processed / totalObjects) * 100),
          description: `Fetching ACLs: ${processed}/${totalObjects} objects`,
        });
      });
      for (const entry of computerAcls) {
        allAclEntries.push(entry);
      }

      // 4. Fetch ACLs for critical system objects
      const systemObjects = [baseDN, `CN=AdminSDHolder,CN=System,${baseDN}`, `CN=Policies,CN=System,${baseDN}`];
      const systemAcls = await this.fetchAclsForObjects(systemObjects, (count) => {
        processed += count;
        this.jobStore.updateStepProgress(jobId, 'FETCHING_ACLS', {
          progress: Math.round((processed / totalObjects) * 100),
          description: `Fetching ACLs: ${processed}/${totalObjects} objects`,
        });
      });
      for (const entry of systemAcls) {
        allAclEntries.push(entry);
      }

      return allAclEntries;
    } catch (error) {
      logger.warn('Failed to fetch ACL entries - insufficient permissions or unsupported configuration');
      return [];
    }
  }

  /**
   * Fetch ACLs for a list of object DNs with progress callback
   */
  private async fetchAclsForObjects(
    objectDns: string[],
    onProgress?: (processedCount: number) => void
  ): Promise<AclEntry[]> {
    const allAclEntries: AclEntry[] = [];

    const BATCH_SIZE = 100;
    for (let i = 0; i < objectDns.length; i += BATCH_SIZE) {
      const batch = objectDns.slice(i, i + BATCH_SIZE);

      const batchPromises = batch.map(async (dn) => {
        try {
          const results = await this.ldapProvider.search<any>(dn, {
            filter: '(objectClass=*)',
            attributes: ['nTSecurityDescriptor'],
            scope: 'base',
            controls: [createSDFlagsControl()],
          });

          if (results.length > 0 && results[0].nTSecurityDescriptor) {
            const secDescriptor = results[0].nTSecurityDescriptor;
            const buffer = Buffer.isBuffer(secDescriptor)
              ? secDescriptor
              : Buffer.from(secDescriptor, 'binary');
            const entries = parseSecurityDescriptor(buffer, dn);
            return entries;
          }
        } catch (error) {
          return [];
        }
        return [];
      });

      const batchResults = await Promise.all(batchPromises);
      batchResults.forEach((entries) => allAclEntries.push(...entries));

      // Report progress
      if (onProgress) {
        onProgress(batch.length);
      }
    }

    return allAclEntries;
  }

  /**
   * Fetch domain configuration
   */
  private async fetchDomainConfig(domain: ADDomain | null): Promise<DomainConfig> {
    const baseDN = this.ldapProvider.getBaseDN();

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
      // Fetch password policy
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
        config.passwordPolicy.complexity = (parseInt(policy.pwdProperties || '0', 10) & 1) === 1;
        config.domainInfo.domainName = policy.name || '';
      }

      if (domain) {
        config.domainInfo.domainMode = this.getDomainModeName(domain.domainFunctionalLevel);
        config.domainInfo.forestMode = this.getDomainModeName(domain.forestFunctionalLevel);
        config.domainInfo.forestName = this.extractDomainNameFromDN(baseDN);
        config.domainInfo.domainName = this.extractDomainNameFromDN(baseDN);
      }

      // Fetch domain controllers
      const dcResults = await this.ldapProvider.search<any>(baseDN, {
        filter: '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
        attributes: ['dNSHostName', 'name'],
        scope: 'sub',
      });

      config.domainInfo.domainControllers = dcResults
        .map((dc: any) => dc.dNSHostName || dc.name)
        .filter((name: string) => name);

      // Fetch FSMO roles
      await this.fetchFSMORoles(config, baseDN);

      // Fetch trusts
      await this.fetchTrusts(config, baseDN);

      // Fetch GPO count
      await this.fetchGPOCount(config, baseDN);

      // Fetch Kerberos policy via SMB (or use defaults)
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

  private formatFiletimeDuration(filetime: any): string {
    if (!filetime) return 'Not configured';
    const value = typeof filetime === 'string' ? parseInt(filetime, 10) : filetime;
    if (value === 0 || isNaN(value)) return 'Not configured';

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

  private extractDomainNameFromDN(dn: string): string {
    const parts = dn.match(/DC=([^,]+)/gi);
    if (!parts) return dn;
    return parts.map((p) => p.replace(/DC=/i, '')).join('.');
  }

  private async fetchFSMORoles(config: DomainConfig, baseDN: string): Promise<void> {
    try {
      const domainRoles = await this.ldapProvider.search<any>(baseDN, {
        filter: '(objectClass=domain)',
        attributes: ['fSMORoleOwner'],
        scope: 'base',
      });

      if (domainRoles.length > 0 && domainRoles[0].fSMORoleOwner) {
        config.domainInfo.fsmoRoles.pdcEmulator = this.extractServerFromDN(domainRoles[0].fSMORoleOwner);
      }

      const ridResults = await this.ldapProvider.search<any>(`CN=RID Manager$,CN=System,${baseDN}`, {
        filter: '(objectClass=*)',
        attributes: ['fSMORoleOwner'],
        scope: 'base',
      });

      if (ridResults.length > 0 && ridResults[0].fSMORoleOwner) {
        config.domainInfo.fsmoRoles.ridMaster = this.extractServerFromDN(ridResults[0].fSMORoleOwner);
      }

      const infraResults = await this.ldapProvider.search<any>(`CN=Infrastructure,${baseDN}`, {
        filter: '(objectClass=*)',
        attributes: ['fSMORoleOwner'],
        scope: 'base',
      });

      if (infraResults.length > 0 && infraResults[0].fSMORoleOwner) {
        config.domainInfo.fsmoRoles.infrastructureMaster = this.extractServerFromDN(
          infraResults[0].fSMORoleOwner
        );
      }
    } catch (error) {
      logger.debug('Could not fetch all FSMO roles', { error });
    }
  }

  private extractServerFromDN(dn: string): string {
    const match = dn.match(/CN=NTDS Settings,CN=([^,]+)/i);
    return match && match[1] ? match[1] : dn;
  }

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
          transitive: (attributes & 1) === 1,
        };
      });
    } catch (error) {
      logger.debug('Could not fetch trust relationships', { error });
    }
  }

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

  private getTrustType(type: number): 'forest' | 'external' | 'realm' | 'shortcut' {
    switch (type) {
      case 1:
        return 'external';
      case 2:
        return 'external';
      case 3:
        return 'realm';
      case 4:
        return 'external';
      default:
        return 'external';
    }
  }

  private async fetchGPOCount(config: DomainConfig, baseDN: string): Promise<void> {
    try {
      const gpoResults = await this.ldapProvider.search<any>(`CN=Policies,CN=System,${baseDN}`, {
        filter: '(objectClass=groupPolicyContainer)',
        attributes: ['cn', 'gPCFileSysPath'],
        scope: 'one',
      });

      config.gpoSummary.totalGPOs = gpoResults.length;

      const linkedResults = await this.ldapProvider.search<any>(baseDN, {
        filter: '(gPLink=*)',
        attributes: ['gPLink'],
        scope: 'sub',
        sizeLimit: 1000,
      });

      const linkedGPOs = new Set<string>();
      linkedResults.forEach((obj: any) => {
        const gpLink = obj.gPLink;
        if (gpLink) {
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
  private async fetchGPOsWithAcls(): Promise<{ gpos: ADGPO[]; links: GPOLink[] }> {
    const baseDN = this.ldapProvider.getBaseDN();
    const gpos: ADGPO[] = [];
    const links: GPOLink[] = [];

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

    return { gpos, links };
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
}
