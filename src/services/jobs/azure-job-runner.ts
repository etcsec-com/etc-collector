/**
 * Azure Job Runner
 *
 * Executes Azure AD audits asynchronously with step-by-step progress tracking.
 * Each step reports progress to JobStore for polling clients.
 */

import { GraphProvider } from '../../providers/azure/graph.provider';
import { AzureUser, AzureGroup, AzureApp, AzurePolicy } from '../../types/azure.types';
import { Finding } from '../../types/finding.types';
import { calculateSecurityScore, SecurityScore } from '../audit/scoring.service';
import { logger } from '../../utils/logger';
import { JobStore } from './job-store';
import { Job, JobType } from './job.types';

// Import all Azure detectors
import { detectUserSecurityVulnerabilities } from '../audit/detectors/azure/user-security.detector';
import { detectAppSecurityVulnerabilities } from '../audit/detectors/azure/app-security.detector';
import { detectConditionalAccessVulnerabilities } from '../audit/detectors/azure/conditional-access.detector';
import { detectPrivilegeSecurityVulnerabilities } from '../audit/detectors/azure/privilege-security.detector';

/**
 * Audit options for Azure job runner
 */
export interface AzureJobRunnerOptions {
  includeDetails?: boolean;
  maxUsers?: number;
  maxGroups?: number;
  maxApps?: number;
}

/**
 * Azure audit result
 */
export interface AzureAuditResult {
  score: SecurityScore;
  findings: Finding[];
  stats: {
    totalUsers: number;
    enabledUsers: number;
    disabledUsers: number;
    totalGroups: number;
    totalApps: number;
    totalPolicies: number;
    totalFindings: number;
    executionTimeMs: number;
  };
  timestamp: Date;
}

/**
 * Azure Job Runner - Executes Azure AD audits with progress tracking
 */
export class AzureJobRunner {
  private jobStore: JobStore;
  private graphProvider: GraphProvider;

  constructor(graphProvider: GraphProvider) {
    this.jobStore = JobStore.getInstance();
    this.graphProvider = graphProvider;
  }

  /**
   * Start an async Azure audit job
   * Returns immediately with job ID, audit runs in background
   */
  startAudit(options: AzureJobRunnerOptions = {}): Job {
    const job = this.jobStore.createJob({
      type: 'azure-audit' as JobType,
      options: options as Record<string, unknown>,
    });

    // Start audit in background (don't await)
    this.runAuditAsync(job.job_id, options).catch((error) => {
      logger.error('Async Azure audit failed', { job_id: job.job_id, error });
    });

    return job;
  }

  /**
   * Run the audit asynchronously with step progress updates
   */
  private async runAuditAsync(jobId: string, options: AzureJobRunnerOptions): Promise<void> {
    const startTime = Date.now();
    const { includeDetails = false, maxUsers, maxGroups, maxApps } = options;

    try {
      // Mark job as running
      this.jobStore.startJob(jobId);

      // ===== STEP 1: AUTHENTICATING =====
      this.jobStore.startStep(jobId, 'AUTHENTICATING', 'Authenticating with Microsoft Graph');
      await this.graphProvider.authenticate();
      this.jobStore.completeStep(jobId, 'AUTHENTICATING');

      // ===== STEP 2: FETCHING_USERS =====
      this.jobStore.startStep(jobId, 'FETCHING_USERS', 'Fetching users from Azure AD');
      const users = await this.fetchUsers(maxUsers);
      this.jobStore.completeStep(jobId, 'FETCHING_USERS', { count: users.length });

      // ===== STEP 3: FETCHING_GROUPS =====
      this.jobStore.startStep(jobId, 'FETCHING_GROUPS', 'Fetching groups from Azure AD');
      const groups = await this.fetchGroups(maxGroups);
      this.jobStore.completeStep(jobId, 'FETCHING_GROUPS', { count: groups.length });

      // ===== STEP 4: FETCHING_APPS =====
      this.jobStore.startStep(jobId, 'FETCHING_APPS', 'Fetching applications from Azure AD');
      const apps = await this.fetchApplications(maxApps);
      this.jobStore.completeStep(jobId, 'FETCHING_APPS', { count: apps.length });

      // ===== STEP 5: FETCHING_POLICIES =====
      this.jobStore.startStep(jobId, 'FETCHING_POLICIES', 'Fetching Conditional Access policies');
      const policies = await this.fetchPolicies();
      this.jobStore.completeStep(jobId, 'FETCHING_POLICIES', { count: policies.length });

      // ===== STEP 6: FETCHING_ROLES =====
      this.jobStore.startStep(jobId, 'FETCHING_ROLES', 'Fetching directory role assignments');
      const roleMap = await this.fetchRoleAssignments(users);
      this.jobStore.completeStep(jobId, 'FETCHING_ROLES', { count: roleMap.size });

      // ===== STEP 7: DETECTING_USER_SECURITY =====
      this.jobStore.startStep(jobId, 'DETECTING_USER_SECURITY', 'Analyzing user security vulnerabilities');
      const userFindings = detectUserSecurityVulnerabilities(users, roleMap, includeDetails);
      this.jobStore.completeStep(jobId, 'DETECTING_USER_SECURITY', { findings: userFindings.length });

      // ===== STEP 8: DETECTING_PRIVILEGE_SECURITY =====
      this.jobStore.startStep(jobId, 'DETECTING_PRIVILEGE_SECURITY', 'Analyzing privilege security vulnerabilities');
      const privilegeFindings = detectPrivilegeSecurityVulnerabilities(users, groups, roleMap, includeDetails);
      this.jobStore.completeStep(jobId, 'DETECTING_PRIVILEGE_SECURITY', { findings: privilegeFindings.length });

      // ===== STEP 9: DETECTING_APP_SECURITY =====
      this.jobStore.startStep(jobId, 'DETECTING_APP_SECURITY', 'Analyzing application security vulnerabilities');
      const appFindings = detectAppSecurityVulnerabilities(apps, includeDetails);
      this.jobStore.completeStep(jobId, 'DETECTING_APP_SECURITY', { findings: appFindings.length });

      // ===== STEP 10: DETECTING_CONDITIONAL_ACCESS =====
      this.jobStore.startStep(jobId, 'DETECTING_CONDITIONAL_ACCESS', 'Analyzing Conditional Access vulnerabilities');
      const caFindings = detectConditionalAccessVulnerabilities(policies, includeDetails);
      this.jobStore.completeStep(jobId, 'DETECTING_CONDITIONAL_ACCESS', { findings: caFindings.length });

      // Aggregate all findings
      const findings: Finding[] = [
        ...userFindings,
        ...privilegeFindings,
        ...appFindings,
        ...caFindings,
      ];

      // ===== STEP 11: CALCULATING_SCORE =====
      this.jobStore.startStep(jobId, 'CALCULATING_SCORE', 'Calculating security score');
      const score = calculateSecurityScore(findings, users.length);
      this.jobStore.completeStep(jobId, 'CALCULATING_SCORE');

      // ===== STEP 12: FORMATTING =====
      this.jobStore.startStep(jobId, 'FORMATTING', 'Formatting audit response');
      const executionTimeMs = Date.now() - startTime;

      // Calculate enabled/disabled user counts
      const disabledUsers = users.filter((u) => !u.accountEnabled).length;
      const enabledUsers = users.length - disabledUsers;

      const result: AzureAuditResult = {
        score,
        findings,
        stats: {
          totalUsers: users.length,
          enabledUsers,
          disabledUsers,
          totalGroups: groups.length,
          totalApps: apps.length,
          totalPolicies: policies.length,
          totalFindings: findings.length,
          executionTimeMs,
        },
        timestamp: new Date(),
      };
      this.jobStore.completeStep(jobId, 'FORMATTING');

      // Complete job with result
      this.jobStore.completeJob(jobId, result);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      logger.error('Azure audit job failed', { jobId, error: errorMessage });
      this.jobStore.failJob(jobId, {
        code: 'AZURE_AUDIT_FAILED',
        message: errorMessage,
        step: this.jobStore.getJob(jobId)?.current_step || 'AUTHENTICATING',
      });
    }
  }

  /**
   * Fetch users from Azure AD with all attributes for enriched entities
   */
  private async fetchUsers(maxUsers?: number): Promise<AzureUser[]> {
    try {
      const options = {
        select: [
          // Identity
          'id',
          'userPrincipalName',
          'displayName',
          'mail',
          'givenName',
          'surname',
          // Organization
          'jobTitle',
          'department',
          'companyName',
          'manager',
          'officeLocation',
          'employeeId',
          // Dates
          'createdDateTime',
          'lastSignInDateTime',
          'lastPasswordChangeDateTime',
          // Security
          'accountEnabled',
          'userType',
          'riskLevel',
          'riskState',
          'isMfaRegistered',
          'strongAuthenticationMethods',
          'assignedLicenses',
          'passwordPolicies',
        ],
        expand: ['manager($select=id,displayName)'],
        top: maxUsers,
      };

      return await this.graphProvider.getUsers(options);
    } catch (error) {
      logger.error('Failed to fetch users:', error);
      return [];
    }
  }

  /**
   * Fetch groups from Azure AD
   */
  private async fetchGroups(maxGroups?: number): Promise<AzureGroup[]> {
    try {
      const options = {
        select: ['id', 'displayName', 'mailEnabled', 'securityEnabled', 'groupTypes', 'membershipRule'],
        top: maxGroups,
      };

      return await this.graphProvider.getGroups(options);
    } catch (error) {
      logger.error('Failed to fetch groups:', error);
      return [];
    }
  }

  /**
   * Fetch applications from Azure AD
   */
  private async fetchApplications(maxApps?: number): Promise<AzureApp[]> {
    try {
      const options = {
        select: [
          'id',
          'appId',
          'displayName',
          'createdDateTime',
          'signInAudience',
          'requiredResourceAccess',
          'passwordCredentials',
          'keyCredentials',
        ],
        top: maxApps,
      };

      return await this.graphProvider.getApplications(options);
    } catch (error) {
      logger.error('Failed to fetch applications:', error);
      return [];
    }
  }

  /**
   * Fetch Conditional Access policies from Azure AD
   */
  private async fetchPolicies(): Promise<AzurePolicy[]> {
    try {
      return await this.graphProvider.getPolicies();
    } catch (error) {
      logger.error('Failed to fetch policies:', error);
      return [];
    }
  }

  /**
   * Fetch role assignments and build a map of userId -> roleIds
   */
  private async fetchRoleAssignments(_users: AzureUser[]): Promise<Map<string, string[]>> {
    const roleMap = new Map<string, string[]>();

    try {
      // Note: In a real implementation, we would fetch directory roles and their members
      // This would be implemented by calling:
      // - GET /directoryRoles (to get all roles)
      // - GET /directoryRoles/{roleId}/members (to get members of each role)
      logger.warn('Role assignment fetching not yet fully implemented - role-based detectors will be limited');
      return roleMap;
    } catch (error) {
      logger.warn('Failed to fetch role assignments:', error);
      return roleMap;
    }
  }
}
