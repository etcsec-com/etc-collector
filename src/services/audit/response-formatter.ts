/**
 * Audit Response Formatter
 *
 * Transforms audit results into PRD FR55-compliant structure
 * Story 1.10: API Controllers & Routes
 */

import {
  AffectedUserEntity,
  AffectedAzureUserEntity,
  AffectedAppEntity,
  AffectedGroupEntity,
  AffectedComputerEntity,
  Finding,
  Severity,
} from '../../types/finding.types';
import { SecurityScore } from './scoring.service';
import { normalizeTypeName } from '../../utils/type-name-normalizer';
import { AttackGraphExport } from '../../types/attack-graph.types';

/**
 * Domain metadata
 */
export interface DomainMetadata {
  name: string;
  baseDN: string;
  ldapUrl: string;
}

/**
 * Audit options
 */
export interface AuditOptionsMetadata {
  includeDetails: boolean;
  includeComputers: boolean;
  includeConfig: boolean;
}

/**
 * Execution metadata
 */
export interface ExecutionMetadata {
  timestamp: string;
  duration: string;
}

/**
 * Audit metadata section
 */
export interface AuditMetadata {
  provider: string;
  domain: DomainMetadata;
  options: AuditOptionsMetadata;
  execution: ExecutionMetadata;
}

/**
 * Objects summary
 */
export interface ObjectsSummary {
  users: number;
  users_enabled: number;
  users_disabled: number;
  groups: number;
  ous: number;
  computers: number;
}

/**
 * Risk summary
 */
export interface RiskSummary {
  score: number;
  rating: string;
  findings: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
    /** Total instances (e.g., ACEs) for forensics - only if different from total */
    totalInstances?: number;
  };
}

/**
 * Audit summary section
 */
export interface AuditSummary {
  objects: ObjectsSummary;
  risk: RiskSummary;
}

/**
 * Finding entry in section
 */
export interface SectionFinding {
  type: string;
  severity: Severity;
  title: string;
  description: string;
  /** Number of affected objects (for scoring & remediation) */
  count: number;
  /** Total instances (e.g., ACEs) for forensics - only present when different from count */
  totalInstances?: number;
  affectedEntities?: (
    | string
    | AffectedUserEntity
    | AffectedAzureUserEntity
    | AffectedAppEntity
    | AffectedGroupEntity
    | AffectedComputerEntity
  )[];
  details?: Record<string, unknown>;
}

/**
 * Section with findings
 */
export interface FindingsSection {
  total: number;
  findings: SectionFinding[];
}

/**
 * Security section (passwords, kerberos, advanced)
 */
export interface SecuritySection {
  passwords: FindingsSection;
  kerberos: FindingsSection;
  advanced: FindingsSection;
}

/**
 * Accounts section (status, privileged, service, dangerous)
 */
export interface AccountsSection {
  status: FindingsSection;
  privileged: FindingsSection;
  service: FindingsSection;
  dangerous: FindingsSection;
}

/**
 * Password policy configuration
 */
export interface PasswordPolicy {
  minPasswordLength: number;
  passwordHistoryLength: number;
  maxPasswordAge: string;
  minPasswordAge: string;
  lockoutThreshold: number;
  lockoutDuration: string;
  lockoutObservationWindow: string;
  complexity: boolean;
}

/**
 * Domain information
 */
export interface DomainInfo {
  forestName: string;
  domainName: string;
  domainMode: string;
  forestMode: string;
  domainControllers: string[];
  fsmoRoles: {
    schemaMaster?: string;
    domainNamingMaster?: string;
    pdcEmulator?: string;
    ridMaster?: string;
    infrastructureMaster?: string;
  };
}

/**
 * Trust relationship
 */
export interface TrustRelationship {
  name: string;
  direction: 'inbound' | 'outbound' | 'bidirectional';
  type: 'forest' | 'external' | 'realm' | 'shortcut';
  transitive: boolean;
}

/**
 * GPO summary
 */
export interface GPOSummary {
  totalGPOs: number;
  linkedGPOs: number;
}

/**
 * Kerberos policy configuration
 */
export interface KerberosPolicy {
  maxTicketAge: string;
  maxRenewAge: string;
  maxServiceAge: string;
  maxClockSkew: string;
  ticketValidateClient: boolean;
  /** true if using Windows default values (GPO not customized) */
  isDefault: boolean;
}

/**
 * Domain configuration
 */
export interface DomainConfig {
  passwordPolicy: PasswordPolicy;
  kerberosPolicy?: KerberosPolicy;
  domainInfo: DomainInfo;
  trusts: TrustRelationship[];
  gpoSummary: GPOSummary;
}

/**
 * ADCS (AD Certificate Services) section
 */
export interface ADCSSection {
  total: number;
  findings: SectionFinding[];
}

/**
 * GPO Security section
 */
export interface GPOSecuritySection {
  total: number;
  findings: SectionFinding[];
}

/**
 * Trusts Analysis section
 */
export interface TrustsAnalysisSection {
  total: number;
  findings: SectionFinding[];
}

/**
 * Full audit response structure (PRD FR55)
 */
export interface ADAuditResponse {
  success: boolean;
  provider: 'active-directory';
  audit: {
    metadata: AuditMetadata;
    summary: AuditSummary;
    security: SecuritySection;
    accounts: AccountsSection;
    groups: FindingsSection;
    computers: FindingsSection;
    permissions: FindingsSection;
    temporal: FindingsSection;
    extendedConfig: FindingsSection;
    adcs: ADCSSection;
    gpoSecurity: GPOSecuritySection;
    trustsAnalysis: TrustsAnalysisSection;
    domainConfig?: DomainConfig;
    attackGraph?: AttackGraphExport;
  };
}

/**
 * Formatter context
 */
export interface FormatterContext {
  domain: DomainMetadata;
  options: {
    includeDetails: boolean;
    includeComputers?: boolean;
    includeConfig?: boolean;
  };
  executionTimeMs: number;
  timestamp: Date;
  domainConfig?: DomainConfig;
  attackGraph?: AttackGraphExport;
}

/**
 * Classify accounts findings into subcategories
 */
function classifyAccountsFinding(finding: Finding): 'status' | 'privileged' | 'service' | 'dangerous' {
  const type = finding.type.toUpperCase();

  // Status-related findings (disabled, inactive, expired)
  if (
    type.includes('DISABLED') ||
    type.includes('INACTIVE') ||
    type.includes('EXPIRED') ||
    type.includes('NEVER_LOGGED') ||
    type.includes('LOCKED')
  ) {
    return 'status';
  }

  // Privileged accounts findings
  if (
    type.includes('ADMIN') ||
    type.includes('PROTECTED_USERS') ||
    type.includes('DOMAIN_CONTROLLER') ||
    type.includes('ENTERPRISE_ADMIN') ||
    type.includes('SCHEMA_ADMIN') ||
    type.includes('SENSITIVE_DELEGATION')
  ) {
    return 'privileged';
  }

  // Service accounts findings
  if (
    type.includes('SERVICE') ||
    type.includes('SPN') ||
    type.includes('DELEGATION') ||
    type.includes('CONSTRAINED') ||
    type.includes('UNCONSTRAINED') ||
    type.includes('RBCD')
  ) {
    return 'service';
  }

  // Dangerous patterns (test, shared, operators, etc.)
  return 'dangerous';
}

/**
 * Convert Finding to SectionFinding
 * Normalizes type names to canonical form for consistent reporting
 */
function toSectionFinding(finding: Finding): SectionFinding {
  const result: SectionFinding = {
    type: normalizeTypeName(finding.type),
    severity: finding.severity,
    title: finding.title,
    description: finding.description,
    count: finding.count,
  };

  // Include totalInstances for forensics (pentesters need this)
  if (finding.totalInstances !== undefined && finding.totalInstances !== finding.count) {
    result.totalInstances = finding.totalInstances;
  }

  if (finding.affectedEntities && finding.affectedEntities.length > 0) {
    result.affectedEntities = finding.affectedEntities;
  }

  if (finding.details && Object.keys(finding.details).length > 0) {
    result.details = finding.details;
  }

  return result;
}

/**
 * Create empty findings section
 */
function createEmptySection(): FindingsSection {
  return { total: 0, findings: [] };
}

/**
 * Format duration in human-readable form
 */
function formatDuration(ms: number): string {
  if (ms < 1000) {
    return `${ms}ms`;
  }
  const seconds = ms / 1000;
  if (seconds < 60) {
    return `${seconds.toFixed(2)}s`;
  }
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  return `${minutes}m ${remainingSeconds.toFixed(0)}s`;
}

/**
 * Extract domain name from base DN
 */
function extractDomainName(baseDN: string): string {
  // Convert DC=example,DC=com to example.com
  const parts = baseDN.match(/DC=([^,]+)/gi);
  if (!parts) return baseDN;
  return parts.map((p) => p.replace(/DC=/i, '')).join('.');
}

/**
 * Format AD audit result to PRD FR55 structure
 */
export function formatADAuditResponse(
  score: SecurityScore,
  findings: Finding[],
  stats: {
    totalUsers: number;
    enabledUsers: number;
    disabledUsers: number;
    totalGroups: number;
    totalComputers: number;
    totalOUs: number;
    totalFindings: number;
    executionTimeMs: number;
  },
  context: FormatterContext
): ADAuditResponse {
  // Initialize sections
  const security: SecuritySection = {
    passwords: createEmptySection(),
    kerberos: createEmptySection(),
    advanced: createEmptySection(),
  };

  const accounts: AccountsSection = {
    status: createEmptySection(),
    privileged: createEmptySection(),
    service: createEmptySection(),
    dangerous: createEmptySection(),
  };

  const groups = createEmptySection();
  const computers = createEmptySection();
  const permissions = createEmptySection();
  const temporal = createEmptySection();
  const extendedConfig = createEmptySection();
  const adcs = createEmptySection();
  const gpoSecurity = createEmptySection();
  const trustsAnalysis = createEmptySection();

  // Classify findings into sections
  for (const finding of findings) {
    const sectionFinding = toSectionFinding(finding);

    switch (finding.category) {
      case 'passwords':
        security.passwords.findings.push(sectionFinding);
        security.passwords.total += finding.count;
        break;

      case 'kerberos':
        security.kerberos.findings.push(sectionFinding);
        security.kerberos.total += finding.count;
        break;

      case 'advanced':
        security.advanced.findings.push(sectionFinding);
        security.advanced.total += finding.count;
        break;

      case 'accounts': {
        const subCategory = classifyAccountsFinding(finding);
        accounts[subCategory].findings.push(sectionFinding);
        accounts[subCategory].total += finding.count;
        break;
      }

      case 'groups':
        groups.findings.push(sectionFinding);
        groups.total += finding.count;
        break;

      case 'computers':
        computers.findings.push(sectionFinding);
        computers.total += finding.count;
        break;

      case 'permissions':
        permissions.findings.push(sectionFinding);
        permissions.total += finding.count;
        break;

      case 'config':
        extendedConfig.findings.push(sectionFinding);
        extendedConfig.total += finding.count;
        break;

      case 'adcs':
        adcs.findings.push(sectionFinding);
        adcs.total += finding.count;
        break;

      case 'gpo':
        gpoSecurity.findings.push(sectionFinding);
        gpoSecurity.total += finding.count;
        break;

      case 'trusts':
        trustsAnalysis.findings.push(sectionFinding);
        trustsAnalysis.total += finding.count;
        break;

      default:
        // Catch-all for any unmapped categories
        extendedConfig.findings.push(sectionFinding);
        extendedConfig.total += finding.count;
    }

    // Check for temporal-related findings (cross-category)
    const type = finding.type.toUpperCase();
    if (
      type.includes('STALE') ||
      type.includes('OLD_') ||
      type.includes('_AGE') ||
      type.includes('LAST_SET') ||
      type.includes('_DAYS')
    ) {
      temporal.findings.push(sectionFinding);
      temporal.total += finding.count;
    }
  }

  // Sort findings by severity then count
  const sortFindings = (a: SectionFinding, b: SectionFinding) => {
    const severityOrder: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
    if (severityOrder[a.severity] !== severityOrder[b.severity]) {
      return severityOrder[a.severity] - severityOrder[b.severity];
    }
    return b.count - a.count;
  };

  // Sort all sections
  security.passwords.findings.sort(sortFindings);
  security.kerberos.findings.sort(sortFindings);
  security.advanced.findings.sort(sortFindings);
  accounts.status.findings.sort(sortFindings);
  accounts.privileged.findings.sort(sortFindings);
  accounts.service.findings.sort(sortFindings);
  accounts.dangerous.findings.sort(sortFindings);
  groups.findings.sort(sortFindings);
  computers.findings.sort(sortFindings);
  permissions.findings.sort(sortFindings);
  temporal.findings.sort(sortFindings);
  extendedConfig.findings.sort(sortFindings);
  adcs.findings.sort(sortFindings);
  gpoSecurity.findings.sort(sortFindings);
  trustsAnalysis.findings.sort(sortFindings);

  return {
    success: true,
    provider: 'active-directory',
    audit: {
      metadata: {
        provider: 'active-directory',
        domain: {
          name: extractDomainName(context.domain.baseDN),
          baseDN: context.domain.baseDN,
          ldapUrl: context.domain.ldapUrl,
        },
        options: {
          includeDetails: context.options.includeDetails,
          includeComputers: context.options.includeComputers ?? true,
          includeConfig: context.options.includeConfig ?? true,
        },
        execution: {
          timestamp: context.timestamp.toISOString(),
          duration: formatDuration(context.executionTimeMs),
        },
      },
      summary: {
        objects: {
          users: stats.totalUsers,
          users_enabled: stats.enabledUsers,
          users_disabled: stats.disabledUsers,
          groups: stats.totalGroups,
          ous: stats.totalOUs,
          computers: stats.totalComputers,
        },
        risk: {
          score: score.score,
          rating: score.rating,
          findings: {
            critical: score.findings.critical,
            high: score.findings.high,
            medium: score.findings.medium,
            low: score.findings.low,
            total: score.findings.total,
            // Total instances for forensics (pentesters) - only if different
            ...((() => {
              const totalInstances = findings.reduce(
                (sum, f) => sum + (f.totalInstances ?? f.count),
                0
              );
              return totalInstances !== score.findings.total
                ? { totalInstances }
                : {};
            })()),
          },
        },
      },
      security,
      accounts,
      groups,
      computers,
      permissions,
      temporal,
      extendedConfig,
      adcs,
      gpoSecurity,
      trustsAnalysis,
      ...(context.domainConfig && { domainConfig: context.domainConfig }),
      ...(context.attackGraph && { attackGraph: context.attackGraph }),
    },
  };
}
