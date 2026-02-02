import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { TokenRepository } from '../../data/repositories/token.repository';
import { CryptoService } from './crypto.service';
import type { Logger } from 'winston';
import { logger } from '../../utils/logger';
import {
  TokenExpiredError,
  TokenRevokedError,
  UsageLimitExceededError,
  TokenNotFoundError,
  InvalidSignatureError,
  InvalidTokenError,
} from './errors';

/**
 * TokenService
 *
 * Manages JWT token lifecycle: generation, validation, revocation, and usage tracking.
 *
 * Features:
 * - RS256 JWT signatures with RSA key pairs
 * - Token usage quotas (max_uses)
 * - Token revocation
 * - Expiration management
 * - Usage tracking
 *
 * Task 2: JWT Token Service (Story 1.4)
 */

export interface GenerateTokenRequest {
  expiresIn: string; // e.g., '1h', '7d', '30d'
  maxUses: number; // 0 = unlimited
  metadata?: Record<string, any>;
}

export interface TokenPayload {
  jti: string; // JWT ID (unique identifier)
  iss: string; // Issuer (always 'etc-collector')
  sub: string; // Subject (always 'system')
  iat: number; // Issued at (Unix timestamp)
  exp: number; // Expiration (Unix timestamp)
  service: string; // Service name (always 'etc-collector')
  maxUses: number; // Maximum allowed uses
}

export interface TokenInfo {
  jti: string;
  created_at: string;
  expires_at: string;
  max_uses: number;
  used_count: number;
  remaining_uses: number; // Calculated
  revoked: boolean;
  revoked_at: string | null;
  revoked_reason: string | null;
}

export class TokenService {
  private logger: Logger;

  constructor(
    private tokenRepo: TokenRepository,
    private cryptoService: CryptoService
  ) {
    this.logger = logger;
  }

  /**
   * Generate a new JWT token with usage quotas
   *
   * Flow:
   * 1. Generate unique jti (UUID v4)
   * 2. Calculate expiration timestamp
   * 3. Create JWT payload with claims
   * 4. Sign token with RS256 private key
   * 5. Save token to database
   * 6. Return signed JWT string
   *
   * @param options Token generation options
   * @returns Signed JWT token string
   */
  async generate(options: GenerateTokenRequest): Promise<string> {
    // 1. Generate unique jti
    const jti = uuidv4();

    // 2. Calculate timestamps
    const iat = Math.floor(Date.now() / 1000); // Unix timestamp (seconds)
    const expirySeconds = this.parseExpiry(options.expiresIn);
    const exp = iat + expirySeconds;

    // 3. Create JWT payload
    const payload: TokenPayload = {
      jti,
      iss: 'etc-collector',
      sub: 'system',
      iat,
      exp,
      service: 'etc-collector',
      maxUses: options.maxUses,
    };

    // 4. Sign token with RS256 private key
    const privateKey = this.cryptoService.getPrivateKey();
    const token = jwt.sign(payload, privateKey, {
      algorithm: 'RS256',
    });

    // 5. Save token to database
    const publicKey = this.cryptoService.getPublicKey();
    const expiresAt = new Date(exp * 1000).toISOString();

    this.tokenRepo.create({
      jti,
      public_key: publicKey,
      expires_at: expiresAt,
      max_uses: options.maxUses,
      metadata: options.metadata ? JSON.stringify(options.metadata) : undefined,
    });

    // 6. Log token generation
    this.logger.info('JWT token generated', {
      jti,
      expiresIn: options.expiresIn,
      expiresAt,
      maxUses: options.maxUses,
    });

    return token;
  }

  /**
   * Validate JWT token and check revocation/usage
   *
   * Flow:
   * 1. Verify JWT signature with RS256 public key
   * 2. Check token expiration (exp claim)
   * 3. Check token issuer (iss claim)
   * 4. Query database for token (by jti)
   * 5. Check if token is revoked
   * 6. Check usage quota (used_count vs max_uses)
   * 7. Return decoded payload if valid
   *
   * @param token JWT token string
   * @returns Decoded token payload
   * @throws TokenExpiredError if token expired
   * @throws TokenRevokedError if token revoked
   * @throws UsageLimitExceededError if usage quota exceeded
   * @throws TokenNotFoundError if jti not in database
   * @throws InvalidSignatureError if JWT verification fails
   * @throws InvalidTokenError if token format invalid
   */
  async validate(token: string): Promise<TokenPayload> {
    let decoded: TokenPayload;

    try {
      // 1. Verify JWT signature with RS256 public key
      const publicKey = this.cryptoService.getPublicKey();
      decoded = jwt.verify(token, publicKey, {
        algorithms: ['RS256'],
      }) as TokenPayload;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        this.logger.warn('Token validation failed: expired');
        throw new TokenExpiredError();
      }
      if (error instanceof jwt.JsonWebTokenError) {
        this.logger.warn('Token validation failed: invalid signature', {
          error: error.message,
        });
        throw new InvalidSignatureError();
      }
      this.logger.error('Token validation failed: unknown error', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      throw new InvalidTokenError('Token validation failed');
    }

    // 2. Check token expiration (redundant with jwt.verify, but explicit)
    const now = Math.floor(Date.now() / 1000);
    if (decoded.exp < now) {
      this.logger.warn('Token expired', { jti: decoded.jti, exp: decoded.exp, now });
      throw new TokenExpiredError();
    }

    // 3. Check token issuer
    if (decoded.iss !== 'etc-collector') {
      this.logger.warn('Token validation failed: invalid issuer', {
        jti: decoded.jti,
        iss: decoded.iss,
      });
      throw new InvalidTokenError('Invalid token issuer');
    }

    // 4. Query database for token
    const tokenRecord = this.tokenRepo.findByJti(decoded.jti);
    if (!tokenRecord) {
      this.logger.warn('Token validation failed: not found in database', {
        jti: decoded.jti,
      });
      throw new TokenNotFoundError();
    }

    // 5. Check if token is revoked
    if (tokenRecord.revoked_at) {
      this.logger.warn('Token validation failed: revoked', {
        jti: decoded.jti,
        revokedAt: tokenRecord.revoked_at,
        revokedBy: tokenRecord.revoked_by,
        revokedReason: tokenRecord.revoked_reason,
      });
      throw new TokenRevokedError();
    }

    // 6. Check usage quota (0 = unlimited)
    if (tokenRecord.max_uses > 0 && tokenRecord.used_count >= tokenRecord.max_uses) {
      this.logger.warn('Token validation failed: usage limit exceeded', {
        jti: decoded.jti,
        usedCount: tokenRecord.used_count,
        maxUses: tokenRecord.max_uses,
      });
      throw new UsageLimitExceededError();
    }

    // 7. Return decoded payload
    this.logger.debug('Token validated successfully', { jti: decoded.jti });
    return decoded;
  }

  /**
   * Revoke a token by jti
   *
   * Flow:
   * 1. Find token in database
   * 2. Check if already revoked
   * 3. Mark as revoked
   * 4. Log revocation
   *
   * @param jti JWT ID
   * @param revokedBy Username or system identifier
   * @param reason Revocation reason
   * @throws TokenNotFoundError if jti not in database
   */
  async revoke(jti: string, revokedBy: string, reason: string): Promise<void> {
    // 1. Find token in database
    const tokenRecord = this.tokenRepo.findByJti(jti);
    if (!tokenRecord) {
      this.logger.warn('Token revocation failed: not found', { jti });
      throw new TokenNotFoundError();
    }

    // 2. Check if already revoked
    if (tokenRecord.revoked_at) {
      this.logger.warn('Token already revoked', {
        jti,
        revokedAt: tokenRecord.revoked_at,
        revokedBy: tokenRecord.revoked_by,
      });
      return; // Idempotent operation
    }

    // 3. Mark as revoked
    this.tokenRepo.revoke(jti, revokedBy, reason);

    // 4. Log revocation
    this.logger.info('Token revoked', {
      jti,
      revokedBy,
      reason,
    });
  }

  /**
   * Get token information by jti
   *
   * Flow:
   * 1. Find token in database
   * 2. Calculate remaining_uses
   * 3. Format response
   * 4. Return token info
   *
   * @param jti JWT ID
   * @returns Token information
   * @throws TokenNotFoundError if jti not in database
   */
  async getInfo(jti: string): Promise<TokenInfo> {
    // 1. Find token in database
    const tokenRecord = this.tokenRepo.findByJti(jti);
    if (!tokenRecord) {
      this.logger.warn('Token info request failed: not found', { jti });
      throw new TokenNotFoundError();
    }

    // 2. Calculate remaining_uses
    const remainingUses =
      tokenRecord.max_uses === 0
        ? -1 // Unlimited
        : Math.max(0, tokenRecord.max_uses - tokenRecord.used_count);

    // 3. Format response
    const info: TokenInfo = {
      jti: tokenRecord.jti,
      created_at: tokenRecord.created_at,
      expires_at: tokenRecord.expires_at,
      max_uses: tokenRecord.max_uses,
      used_count: tokenRecord.used_count,
      remaining_uses: remainingUses,
      revoked: !!tokenRecord.revoked_at,
      revoked_at: tokenRecord.revoked_at || null,
      revoked_reason: tokenRecord.revoked_reason || null,
    };

    // 4. Return token info
    return info;
  }

  /**
   * Increment token usage count
   *
   * Flow:
   * 1. Increment used_count in database
   * 2. Log usage increment
   *
   * @param jti JWT ID
   */
  async incrementUsage(jti: string): Promise<void> {
    // 1. Increment used_count
    this.tokenRepo.incrementUsage(jti);

    // 2. Log usage increment
    this.logger.debug('Token usage incremented', { jti });
  }

  /**
   * List all tokens (including expired and revoked)
   *
   * Flow:
   * 1. Get all tokens from database
   * 2. Map to TokenInfo format
   * 3. Return array of token info
   *
   * @returns Array of token information
   */
  async listAll(): Promise<TokenInfo[]> {
    // 1. Get all tokens
    const tokens = this.tokenRepo.findAll();

    // 2. Map to TokenInfo format
    const tokenInfoList: TokenInfo[] = tokens.map((token) => {
      const remainingUses =
        token.max_uses === 0
          ? -1 // Unlimited
          : Math.max(0, token.max_uses - token.used_count);

      return {
        jti: token.jti,
        created_at: token.created_at,
        expires_at: token.expires_at,
        max_uses: token.max_uses,
        used_count: token.used_count,
        remaining_uses: remainingUses,
        revoked: !!token.revoked_at,
        revoked_at: token.revoked_at || null,
        revoked_reason: token.revoked_reason || null,
      };
    });

    // 3. Return array
    return tokenInfoList;
  }

  /**
   * Parse expiry string to seconds
   *
   * Supports:
   * - s: seconds
   * - m: minutes
   * - h: hours
   * - d: days
   *
   * Examples:
   * - '60s' → 60
   * - '30m' → 1800
   * - '1h' → 3600
   * - '7d' → 604800
   * - '30d' → 2592000
   *
   * @param expiresIn Human-readable duration string
   * @returns Duration in seconds
   * @throws Error if format is invalid
   */
  private parseExpiry(expiresIn: string): number {
    const match = expiresIn.match(/^(\d+)([smhd])$/);
    if (!match || !match[1] || !match[2]) {
      throw new Error(
        `Invalid expiry format: ${expiresIn}. Expected format: <number><unit> (e.g., '1h', '7d')`
      );
    }

    const value = parseInt(match[1], 10);
    const unit = match[2];

    const multipliers: Record<string, number> = {
      s: 1,
      m: 60,
      h: 3600,
      d: 86400,
    };

    const multiplier = multipliers[unit];
    if (multiplier === undefined) {
      throw new Error(`Invalid time unit: ${unit}`);
    }

    const seconds = value * multiplier;

    this.logger.debug('Parsed expiry', { expiresIn, seconds });
    return seconds;
  }
}
