/**
 * Token Types
 */

export type TokenStatus = 'valid' | 'expired' | 'revoked' | 'max_uses_exceeded';

export interface TokenPayload {
  jti: string; // JWT ID
  iat: number; // Issued at (Unix timestamp)
  exp: number; // Expires at (Unix timestamp)
  maxUses: number;
  metadata?: Record<string, string>;
}

export interface TokenInfo {
  jti: string;
  createdAt: string;
  expiresAt: string;
  maxUses: number;
  usedCount: number;
  status: TokenStatus;
  revoked: boolean;
  revokedAt?: string;
  revokedReason?: string;
}

export interface TokenUsage {
  jti: string;
  usedAt: string;
  usedCount: number;
  remainingUses: number;
}
