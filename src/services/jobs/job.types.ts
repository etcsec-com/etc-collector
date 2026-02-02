/**
 * Job Types
 *
 * Types for async audit job management with progress tracking.
 * Supports polling architecture for long-running audit operations.
 */

/**
 * Job status
 */
export type JobStatus = 'pending' | 'running' | 'completed' | 'failed';

/**
 * Step status
 */
export type StepStatus = 'pending' | 'running' | 'completed' | 'failed' | 'skipped';

/**
 * Job type
 */
export type JobType = 'ad-audit' | 'azure-audit';

/**
 * Audit step names (AD + Azure)
 */
export type AuditStepName =
  // Common steps
  | 'CONNECTING'
  | 'FETCHING_USERS'
  | 'FETCHING_GROUPS'
  | 'CALCULATING_SCORE'
  | 'FORMATTING'
  | 'COMPLETED'
  // AD-specific steps
  | 'FETCHING_COMPUTERS'
  | 'FETCHING_DOMAIN'
  | 'FETCHING_ACLS'
  | 'DETECTING_PASSWORDS'
  | 'DETECTING_KERBEROS'
  | 'DETECTING_ACCOUNTS'
  | 'DETECTING_GROUPS'
  | 'DETECTING_COMPUTERS'
  | 'DETECTING_ADVANCED'
  | 'DETECTING_PERMISSIONS'
  | 'FETCHING_CONFIG'
  // Azure-specific steps
  | 'AUTHENTICATING'
  | 'FETCHING_APPS'
  | 'FETCHING_POLICIES'
  | 'FETCHING_ROLES'
  | 'DETECTING_USER_SECURITY'
  | 'DETECTING_PRIVILEGE_SECURITY'
  | 'DETECTING_APP_SECURITY'
  | 'DETECTING_CONDITIONAL_ACCESS';

/**
 * Step definition with weight for progress calculation
 */
export interface StepDefinition {
  name: AuditStepName;
  description: string;
  weight: number; // Percentage weight (0-100)
}

/**
 * AD Audit steps with weights
 */
export const AD_AUDIT_STEPS: StepDefinition[] = [
  { name: 'CONNECTING', description: 'Connecting to LDAP server', weight: 2 },
  { name: 'FETCHING_USERS', description: 'Fetching users from Active Directory', weight: 12 },
  { name: 'FETCHING_GROUPS', description: 'Fetching groups from Active Directory', weight: 8 },
  { name: 'FETCHING_COMPUTERS', description: 'Fetching computers from Active Directory', weight: 8 },
  { name: 'FETCHING_DOMAIN', description: 'Fetching domain information', weight: 2 },
  { name: 'FETCHING_ACLS', description: 'Fetching security descriptors (ACLs)', weight: 15 },
  { name: 'DETECTING_PASSWORDS', description: 'Analyzing password vulnerabilities (7 checks)', weight: 7 },
  { name: 'DETECTING_KERBEROS', description: 'Analyzing Kerberos vulnerabilities (8 checks)', weight: 7 },
  { name: 'DETECTING_ACCOUNTS', description: 'Analyzing account vulnerabilities (15 checks)', weight: 10 },
  { name: 'DETECTING_GROUPS', description: 'Analyzing group vulnerabilities (7 checks)', weight: 5 },
  { name: 'DETECTING_COMPUTERS', description: 'Analyzing computer vulnerabilities (17 checks)', weight: 8 },
  { name: 'DETECTING_ADVANCED', description: 'Analyzing advanced vulnerabilities (22 checks)', weight: 8 },
  { name: 'DETECTING_PERMISSIONS', description: 'Analyzing permission vulnerabilities (9 checks)', weight: 5 },
  { name: 'CALCULATING_SCORE', description: 'Calculating security score', weight: 1 },
  { name: 'FETCHING_CONFIG', description: 'Fetching domain configuration', weight: 2 },
  { name: 'FORMATTING', description: 'Formatting audit response', weight: 0 },
];

/**
 * Azure Audit steps with weights
 */
export const AZURE_AUDIT_STEPS: StepDefinition[] = [
  { name: 'AUTHENTICATING', description: 'Authenticating with Microsoft Graph', weight: 5 },
  { name: 'FETCHING_USERS', description: 'Fetching users from Azure AD', weight: 20 },
  { name: 'FETCHING_GROUPS', description: 'Fetching groups from Azure AD', weight: 10 },
  { name: 'FETCHING_APPS', description: 'Fetching applications from Azure AD', weight: 10 },
  { name: 'FETCHING_POLICIES', description: 'Fetching Conditional Access policies', weight: 5 },
  { name: 'FETCHING_ROLES', description: 'Fetching directory role assignments', weight: 10 },
  { name: 'DETECTING_USER_SECURITY', description: 'Analyzing user security vulnerabilities (10 checks)', weight: 15 },
  { name: 'DETECTING_PRIVILEGE_SECURITY', description: 'Analyzing privilege security vulnerabilities (4 checks)', weight: 10 },
  { name: 'DETECTING_APP_SECURITY', description: 'Analyzing application security vulnerabilities (7 checks)', weight: 8 },
  { name: 'DETECTING_CONDITIONAL_ACCESS', description: 'Analyzing Conditional Access vulnerabilities (6 checks)', weight: 5 },
  { name: 'CALCULATING_SCORE', description: 'Calculating security score', weight: 1 },
  { name: 'FORMATTING', description: 'Formatting audit response', weight: 1 },
];

/**
 * Job step with runtime information
 */
export interface JobStep {
  name: AuditStepName;
  status: StepStatus;
  description: string;
  started_at?: string;
  completed_at?: string;
  duration_ms?: number;
  progress?: number; // 0-100 for current step
  count?: number; // Number of items processed (users, groups, etc.)
  findings?: number; // Number of findings detected
  error?: string;
}

/**
 * Job error details
 */
export interface JobError {
  code: string;
  message: string;
  step: AuditStepName;
  details?: Record<string, unknown>;
}

/**
 * Job with full tracking information
 */
export interface Job<T = unknown> {
  job_id: string;
  type: JobType;
  status: JobStatus;
  progress: number; // 0-100 overall progress
  current_step: AuditStepName;
  description: string;
  started_at: string;
  updated_at: string;
  completed_at?: string;
  failed_at?: string;
  duration_ms?: number;
  steps: JobStep[];
  error?: JobError;
  result?: T; // Audit result when completed
  options?: Record<string, unknown>; // Original audit options
}

/**
 * Job creation options
 */
export interface CreateJobOptions {
  type: JobType;
  options?: Record<string, unknown>;
}

/**
 * Progress update for a step
 */
export interface StepProgressUpdate {
  progress?: number;
  count?: number;
  findings?: number;
  description?: string;
}

/**
 * Job summary for listing
 */
export interface JobSummary {
  job_id: string;
  type: JobType;
  status: JobStatus;
  progress: number;
  current_step: AuditStepName;
  started_at: string;
  completed_at?: string;
  duration_ms?: number;
}
