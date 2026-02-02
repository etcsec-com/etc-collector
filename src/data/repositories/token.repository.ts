import Database from 'better-sqlite3';
import { Token, TokenCreateInput, ActiveToken } from '../models/Token.model';

/**
 * Token Repository
 * Handles CRUD operations for JWT tokens in SQLite database
 * Uses synchronous better-sqlite3 for thread-safe operations
 */
export class TokenRepository {
  constructor(private db: Database.Database) {}

  /**
   * Create a new token record
   * @param input - Token creation data
   * @returns The created token with generated ID
   */
  create(input: TokenCreateInput): Token {
    const stmt = this.db.prepare(`
      INSERT INTO tokens (jti, public_key, expires_at, max_uses, metadata)
      VALUES (@jti, @public_key, @expires_at, @max_uses, @metadata)
    `);

    stmt.run({
      jti: input.jti,
      public_key: input.public_key,
      expires_at: input.expires_at,
      max_uses: input.max_uses ?? 0,
      metadata: input.metadata ?? null,
    });

    return this.findByJti(input.jti)!;
  }

  /**
   * Find a token by its JTI (JWT ID)
   * @param jti - The JWT ID to search for
   * @returns The token if found, null otherwise
   */
  findByJti(jti: string): Token | null {
    const stmt = this.db.prepare(`
      SELECT id, jti, public_key, created_at, expires_at, max_uses, used_count,
             revoked_at, revoked_by, revoked_reason, metadata
      FROM tokens
      WHERE jti = ?
    `);

    return (stmt.get(jti) as Token | undefined) ?? null;
  }

  /**
   * Get all tokens (including expired and revoked)
   * @returns Array of all tokens
   */
  findAll(): Token[] {
    const stmt = this.db.prepare(`
      SELECT id, jti, public_key, created_at, expires_at, max_uses, used_count,
             revoked_at, revoked_by, revoked_reason, metadata
      FROM tokens
      ORDER BY created_at DESC
    `);

    return stmt.all() as Token[];
  }

  /**
   * Get all active tokens (not expired, not revoked, within usage limits)
   * Uses the v_active_tokens view for optimized query
   * @returns Array of active tokens with remaining_uses calculated
   */
  findActive(): ActiveToken[] {
    const stmt = this.db.prepare(`
      SELECT id, jti, created_at, expires_at, max_uses, used_count, remaining_uses
      FROM v_active_tokens
      ORDER BY created_at DESC
    `);

    return stmt.all() as ActiveToken[];
  }

  /**
   * Increment the usage count for a token
   * @param jti - The JWT ID of the token to increment
   * @throws Error if token not found or usage limit exceeded
   */
  incrementUsage(jti: string): void {
    const stmt = this.db.prepare(`
      UPDATE tokens
      SET used_count = used_count + 1
      WHERE jti = ?
        AND (max_uses = 0 OR used_count < max_uses)
        AND revoked_at IS NULL
        AND datetime(expires_at) > datetime('now')
    `);

    const result = stmt.run(jti);

    if (result.changes === 0) {
      throw new Error(`Token not found, expired, revoked, or usage limit exceeded: ${jti}`);
    }
  }

  /**
   * Revoke a token, making it unusable
   * @param jti - The JWT ID to revoke
   * @param revokedBy - Identifier of who revoked the token
   * @param reason - Reason for revocation
   * @throws Error if token not found or already revoked
   */
  revoke(jti: string, revokedBy: string, reason: string): void {
    const stmt = this.db.prepare(`
      UPDATE tokens
      SET revoked_at = datetime('now'),
          revoked_by = ?,
          revoked_reason = ?
      WHERE jti = ?
        AND revoked_at IS NULL
    `);

    const result = stmt.run(revokedBy, reason, jti);

    if (result.changes === 0) {
      throw new Error(`Token not found or already revoked: ${jti}`);
    }
  }

  /**
   * Delete all expired tokens from the database
   * Used for cleanup operations
   * @returns Number of tokens deleted
   */
  deleteExpired(): number {
    const stmt = this.db.prepare(`
      DELETE FROM tokens
      WHERE datetime(expires_at) <= datetime('now')
    `);

    const result = stmt.run();
    return result.changes;
  }

  /**
   * Count total number of tokens
   * @returns Total token count
   */
  count(): number {
    const stmt = this.db.prepare('SELECT COUNT(*) as count FROM tokens');
    const result = stmt.get() as { count: number };
    return result.count;
  }

  /**
   * Count number of active tokens
   * @returns Active token count
   */
  countActive(): number {
    const stmt = this.db.prepare('SELECT COUNT(*) as count FROM v_active_tokens');
    const result = stmt.get() as { count: number };
    return result.count;
  }
}
