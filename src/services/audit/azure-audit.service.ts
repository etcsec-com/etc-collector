/**
 * Azure AD Audit Service
 *
 * Orchestrates Azure vulnerability detection across 27 checks in 4 categories
 * Story 1.8: Azure Vulnerability Detection Engine
 *
 * Architecture:
 * 1. Collect Azure AD data (users, groups, apps, policies)
 * 2. Fetch role assignments and build role map
 * 3. Run all detector categories in parallel
 * 4. Aggregate findings
 * 5. Calculate security score
 * 6. Return audit results
 */

import { GraphProvider } from '../../providers/azure/graph.provider';
import { AzureUser, AzureGroup, AzureApp, AzurePolicy } from '../../types/azure.types';
import { Finding } from '../../types/finding.types';
import { calculateSecurityScore, SecurityScore } from './scoring.service';
import { logger } from '../../utils/logger';

// Import all Azure detectors
import { detectUserSecurityVulnerabilities } from './detectors/azure/user-security.detector';
import { detectAppSecurityVulnerabilities } from './detectors/azure/app-security.detector';
import { detectConditionalAccessVulnerabilities } from './detectors/azure/conditional-access.detector';
import { detectPrivilegeSecurityVulnerabilities } from './detectors/azure/privilege-security.detector';

/**
 * Audit options
 */
export interface AzureAuditOptions {
  /**
   * Include detailed entity names in findings
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
   * Maximum number of applications to fetch (for testing)
   */
  maxApps?: number;
}

/**
 * Audit result
 */
export interface AzureAuditResult {
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
    totalGroups: number;
    totalApps: number;
    totalPolicies: number;
    totalFindings: number;
    executionTimeMs: number;
  };

  /**
   * Timestamp
   */
  timestamp: Date;
}

/**
 * Azure AD Audit Service
 */
export class AzureAuditService {
  constructor(private graphProvider: GraphProvider) {}

  /**
   * Run full Azure AD security audit
   *
   * @param options Audit options
   * @returns Audit results with findings and security score
   */
  async runAudit(options: AzureAuditOptions = {}): Promise<AzureAuditResult> {
    const startTime = Date.now();
    const { includeDetails = false, maxUsers, maxGroups, maxApps } = options;

    // 1. Authenticate with Microsoft Graph
    await this.graphProvider.authenticate();

    // 2. Collect Azure AD data in parallel
    const [users, groups, apps, policies] = await Promise.all([
      this.fetchUsers(maxUsers),
      this.fetchGroups(maxGroups),
      this.fetchApplications(maxApps),
      this.fetchPolicies(),
    ]);

    // 3. Fetch role assignments and build role map
    const roleMap = await this.fetchRoleAssignments(users);

    // 4. Run all detector categories in parallel
    const findings: Finding[] = [];

    const detectorResults = await Promise.all([
      Promise.resolve(detectUserSecurityVulnerabilities(users, roleMap, includeDetails)),
      Promise.resolve(detectAppSecurityVulnerabilities(apps, includeDetails)),
      Promise.resolve(detectConditionalAccessVulnerabilities(policies, includeDetails)),
      Promise.resolve(detectPrivilegeSecurityVulnerabilities(users, groups, roleMap, includeDetails)),
    ]);

    // Flatten all findings
    detectorResults.forEach((categoryFindings) => {
      findings.push(...categoryFindings);
    });

    // 5. Calculate security score
    const score = calculateSecurityScore(findings, users.length);

    // 6. Build result
    const executionTimeMs = Date.now() - startTime;

    return {
      score,
      findings,
      stats: {
        totalUsers: users.length,
        totalGroups: groups.length,
        totalApps: apps.length,
        totalPolicies: policies.length,
        totalFindings: findings.length,
        executionTimeMs,
      },
      timestamp: new Date(),
    };
  }

  /**
   * Test Microsoft Graph connection
   *
   * @returns Connection test result
   */
  async testConnection(): Promise<{ success: boolean; message: string }> {
    try {
      const result = await this.graphProvider.testConnection();
      return {
        success: result.success,
        message: result.message,
      };
    } catch (error) {
      return {
        success: false,
        message: error instanceof Error ? error.message : 'Unknown connection error',
      };
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
        select: ['id', 'displayName', 'mailEnabled', 'securityEnabled', 'groupTypes'],
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
        select: ['id', 'appId', 'displayName', 'createdDateTime', 'signInAudience'],
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
   *
   * This requires calling the directory role members API for each role.
   * Note: This requires Directory.Read.All permission.
   */
  private async fetchRoleAssignments(_users: AzureUser[]): Promise<Map<string, string[]>> {
    const roleMap = new Map<string, string[]>();

    try {
      // Note: In a real implementation, we would fetch directory roles and their members
      // For now, return empty map - role-based detectors will report 0 findings
      // This would be implemented by calling:
      // - GET /directoryRoles (to get all roles)
      // - GET /directoryRoles/{roleId}/members (to get members of each role)

      logger.warn('Role assignment fetching not yet implemented - role-based detectors will be limited');
      return roleMap;
    } catch (error) {
      logger.warn('Failed to fetch role assignments:', error);
      return roleMap;
    }
  }
}
