import { z } from 'zod';

/**
 * Zod schemas for audit endpoints
 */

export const auditRequestSchema = z.object({
  includeDetails: z.boolean().optional().default(false),
  maxUsers: z.number().int().positive().optional(),
  maxGroups: z.number().int().positive().optional(),
  maxComputers: z.number().int().positive().optional(),
  maxApps: z.number().int().positive().optional(),
});

export const exportRequestSchema = z.object({
  auditResult: z.object({
    score: z.object({
      score: z.number(),
      rating: z.string(),
      weightedPoints: z.number(),
      totalUsers: z.number(),
      findings: z.object({
        critical: z.number(),
        high: z.number(),
        medium: z.number(),
        low: z.number(),
        total: z.number(),
      }),
      categories: z.record(z.string(), z.number()),
    }),
    findings: z.array(
      z.object({
        type: z.string(),
        severity: z.enum(['critical', 'high', 'medium', 'low']),
        category: z.string(),
        title: z.string(),
        description: z.string(),
        count: z.number(),
        affectedEntities: z.array(z.string()).optional(),
      })
    ),
    stats: z.object({
      totalUsers: z.number().optional(),
      totalGroups: z.number().optional(),
      totalComputers: z.number().optional(),
      totalApps: z.number().optional(),
      totalPolicies: z.number().optional(),
      totalFindings: z.number(),
      executionTimeMs: z.number(),
    }),
    timestamp: z.coerce.date(),
  }),
  format: z.enum(['json', 'csv']),
  domain: z.string().optional(),
  tenantId: z.string().optional(),
  includeDetails: z.boolean().optional(),
  includeAffectedEntities: z.boolean().optional(),
  delimiter: z.string().length(1).optional(),
});
