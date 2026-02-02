/**
 * DTO for token information response
 */
export interface TokenResponseDto {
  jti: string;
  token?: string;
  createdAt: string;
  expiresAt: string;
  maxUses: number;
  usedCount: number;
  revoked: boolean;
  revokedAt?: string;
  revokedReason?: string;
}
