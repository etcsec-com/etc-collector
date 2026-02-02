import { TokenRepository } from '../repositories/token.repository';
import { logInfo, logError } from '../../utils/logger';

/**
 * Token Cleanup Job
 * Removes expired and old revoked tokens according to retention policy
 *
 * Retention Policy:
 * - Expired tokens (expires_at < now): Deleted immediately if not revoked
 * - Expired + Revoked tokens (expires_at < now AND revoked_at < now - 90 days): Deleted after 90 days
 * - Active tokens: Never deleted
 *
 * This job should be scheduled to run periodically (e.g., daily at 3 AM)
 */
export class TokenCleanupJob {
  constructor(private tokenRepo: TokenRepository) {}

  /**
   * Execute the cleanup job
   * @returns Number of tokens deleted
   */
  run(): number {
    logInfo('Starting token cleanup job');

    try {
      const before = this.tokenRepo.count();

      // Delete expired tokens (90-day retention for revoked)
      const deletedCount = this.deleteExpiredTokens();

      const after = this.tokenRepo.count();

      logInfo('Token cleanup job completed', {
        tokensBefore: before,
        tokensAfter: after,
        deletedCount,
      });

      return deletedCount;
    } catch (error) {
      logError('Token cleanup job failed', error as Error);
      throw error;
    }
  }

  /**
   * Delete expired tokens with 90-day retention for revoked tokens
   * @private
   * @returns Number of tokens deleted
   */
  private deleteExpiredTokens(): number {
    // Query deletes:
    // 1. Non-revoked expired tokens (cleanup immediately)
    // 2. Revoked tokens that expired AND were revoked > 90 days ago (retain for audit)
    const stmt = this.tokenRepo['db'].prepare(`
      DELETE FROM tokens
      WHERE datetime(expires_at) <= datetime('now')
        AND (
          revoked_at IS NULL
          OR datetime(revoked_at) <= datetime('now', '-90 days')
        )
    `);

    const result = stmt.run();
    const deletedCount = result.changes;

    if (deletedCount > 0) {
      logInfo('Deleted expired tokens', { count: deletedCount });
    } else {
      logInfo('No expired tokens to delete');
    }

    return deletedCount;
  }

  /**
   * Get cleanup statistics without deleting anything
   * Useful for monitoring and alerting
   * @returns Cleanup statistics
   */
  getStatistics(): CleanupStatistics {
    const db = this.tokenRepo['db'];

    // Count expired non-revoked tokens (immediate deletion candidates)
    const expiredNonRevoked = db
      .prepare(`
        SELECT COUNT(*) as count FROM tokens
        WHERE datetime(expires_at) <= datetime('now')
          AND revoked_at IS NULL
      `)
      .get() as { count: number };

    // Count old revoked expired tokens (deletion candidates after 90 days)
    const oldRevokedExpired = db
      .prepare(`
        SELECT COUNT(*) as count FROM tokens
        WHERE datetime(expires_at) <= datetime('now')
          AND revoked_at IS NOT NULL
          AND datetime(revoked_at) <= datetime('now', '-90 days')
      `)
      .get() as { count: number };

    // Count recent revoked expired tokens (retained for audit, < 90 days)
    const recentRevokedExpired = db
      .prepare(`
        SELECT COUNT(*) as count FROM tokens
        WHERE datetime(expires_at) <= datetime('now')
          AND revoked_at IS NOT NULL
          AND datetime(revoked_at) > datetime('now', '-90 days')
      `)
      .get() as { count: number };

    const totalDeletionCandidates = expiredNonRevoked.count + oldRevokedExpired.count;

    const stats: CleanupStatistics = {
      totalTokens: this.tokenRepo.count(),
      activeTokens: this.tokenRepo.countActive(),
      expiredNonRevoked: expiredNonRevoked.count,
      oldRevokedExpired: oldRevokedExpired.count,
      recentRevokedExpired: recentRevokedExpired.count,
      totalDeletionCandidates,
    };

    logInfo('Token cleanup statistics', stats as unknown as Record<string, unknown>);

    return stats;
  }

  /**
   * Run cleanup job and return statistics
   * Combines cleanup and reporting in one operation
   * @returns Cleanup result with statistics
   */
  runWithStatistics(): CleanupResult {
    const statsBefore = this.getStatistics();
    const deletedCount = this.run();
    const statsAfter = this.getStatistics();

    return {
      deletedCount,
      statsBefore,
      statsAfter,
    };
  }
}

/**
 * Token cleanup statistics
 */
export interface CleanupStatistics {
  totalTokens: number;
  activeTokens: number;
  expiredNonRevoked: number; // Immediate deletion candidates
  oldRevokedExpired: number; // Deletion candidates after 90 days
  recentRevokedExpired: number; // Retained for audit (< 90 days)
  totalDeletionCandidates: number; // Sum of immediate + old revoked
}

/**
 * Cleanup job result
 */
export interface CleanupResult {
  deletedCount: number;
  statsBefore: CleanupStatistics;
  statsAfter: CleanupStatistics;
}
