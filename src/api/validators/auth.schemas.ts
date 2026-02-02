import { z } from 'zod';

/**
 * Zod Validation Schemas for Authentication Endpoints
 *
 * Provides type-safe request validation for JWT token management.
 *
 * Task 5: Create Zod Validation Schemas (Story 1.4)
 */

/**
 * Generate Token Request Schema
 *
 * Validates token generation requests:
 * - expiresIn: Duration string (e.g., '1h', '7d', '30d')
 * - maxUses: Usage quota (0 = unlimited, >0 = limited uses)
 * - metadata: Optional arbitrary metadata
 */
export const GenerateTokenSchema = z.object({
  expiresIn: z
    .string()
    .regex(/^\d+[smhd]$/, 'Invalid duration format. Expected: <number><unit> (e.g., 1h, 7d)')
    .optional()
    .default('1h'),
  maxUses: z.number().int().min(0, 'maxUses must be >= 0').optional().default(0),
  metadata: z.record(z.string(), z.any()).optional(),
});

/**
 * Validate Token Request Schema
 *
 * Validates token validation requests:
 * - token: JWT token string (non-empty)
 */
export const ValidateTokenSchema = z.object({
  token: z.string().min(1, 'Token is required'),
});

/**
 * Revoke Token Request Schema
 *
 * Validates token revocation requests:
 * - jti: JWT ID (UUID v4 format)
 * - reason: Optional revocation reason
 */
export const RevokeTokenSchema = z.object({
  jti: z.string().uuid('Invalid JWT ID format'),
  reason: z.string().optional(),
});

/**
 * Type Inference from Zod Schemas
 *
 * These types are automatically inferred from the schemas above,
 * ensuring type safety across the application.
 */
export type GenerateTokenRequest = z.infer<typeof GenerateTokenSchema>;
export type ValidateTokenRequest = z.infer<typeof ValidateTokenSchema>;
export type RevokeTokenRequest = z.infer<typeof RevokeTokenSchema>;
