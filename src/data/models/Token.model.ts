/**
 * Token Model
 * Represents a JWT token in the database
 */
export interface Token {
  id: number;
  jti: string;
  public_key: string;
  created_at: string;
  expires_at: string;
  max_uses: number;
  used_count: number;
  revoked_at: string | null;
  revoked_by: string | null;
  revoked_reason: string | null;
  metadata: string | null;
}

export interface TokenCreateInput {
  jti: string;
  public_key: string;
  expires_at: string;
  max_uses?: number;
  metadata?: string;
}

export interface ActiveToken {
  id: number;
  jti: string;
  created_at: string;
  expires_at: string;
  max_uses: number;
  used_count: number;
  remaining_uses: number;
}
