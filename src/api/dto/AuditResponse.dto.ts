/**
 * DTO for audit response structure
 */
export interface AuditResponseDto {
  success: boolean;
  provider: 'active-directory' | 'azure';
  auditId: string;
  timestamp: string;
  summary: {
    totalFindings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    riskScore: number;
  };
  findings?: unknown[]; // Will be properly typed in later stories
  metadata?: Record<string, unknown>;
}
