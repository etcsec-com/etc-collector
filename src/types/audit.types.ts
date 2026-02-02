import { Finding } from './finding.types';

/**
 * Audit Types
 */

export type Provider = 'active-directory' | 'azure';

export interface AuditOptions {
  includeDetails?: boolean;
  includeComputers?: boolean;
  includeConfig?: boolean;
}

export interface AuditSummary {
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  riskScore: number;
  categoryScores?: Record<string, number>;
}

export interface AuditMetadata {
  auditId: string;
  provider: Provider;
  timestamp: string;
  duration: number; // milliseconds
  objectsCounted?: {
    users?: number;
    groups?: number;
    computers?: number;
    policies?: number;
  };
}

export interface AuditResult {
  metadata: AuditMetadata;
  summary: AuditSummary;
  findings: Finding[];
}
