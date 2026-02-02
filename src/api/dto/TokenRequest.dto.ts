/**
 * DTO for token generation request
 */
export interface TokenRequestDto {
  expiresIn?: string;
  maxUses?: number;
  metadata?: Record<string, string>;
}
