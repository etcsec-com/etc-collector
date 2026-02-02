import Database from 'better-sqlite3';
import { TokenRepository } from '../../../src/data/repositories/token.repository';
import { TokenCleanupJob } from '../../../src/data/jobs/token-cleanup.job';

describe('TokenCleanupJob', () => {
  let db: Database.Database;
  let repository: TokenRepository;
  let cleanupJob: TokenCleanupJob;

  // Helper function to create expired token (bypasses CHECK constraint)
  const createExpiredToken = (jti: string, daysAgo = 0): void => {
    // First create with future date
    repository.create({
      jti,
      public_key: 'key',
      expires_at: new Date(Date.now() + 3600000).toISOString(),
    });

    // Then update to expired date and created_at
    if (daysAgo > 0) {
      db.prepare(`UPDATE tokens SET
        created_at = datetime('now', '-${daysAgo + 1} days'),
        expires_at = datetime('now', '-${daysAgo} days')
        WHERE jti = ?`).run(jti);
    } else {
      db.prepare(`UPDATE tokens SET
        created_at = datetime('now', '-2 hours'),
        expires_at = datetime('now', '-1 hour')
        WHERE jti = ?`).run(jti);
    }
  };

  beforeEach(() => {
    // Create in-memory database for testing
    db = new Database(':memory:');

    // Create schema
    db.exec(`
      CREATE TABLE tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        jti TEXT UNIQUE NOT NULL,
        public_key TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        expires_at TEXT NOT NULL,
        max_uses INTEGER NOT NULL DEFAULT 0,
        used_count INTEGER NOT NULL DEFAULT 0,
        revoked_at TEXT,
        revoked_by TEXT,
        revoked_reason TEXT,
        metadata TEXT,
        CONSTRAINT check_usage CHECK (used_count <= max_uses OR max_uses = 0),
        CONSTRAINT check_dates CHECK (datetime(expires_at) > datetime(created_at))
      );

      CREATE VIEW v_active_tokens AS
      SELECT
        id, jti, created_at, expires_at, max_uses, used_count,
        CASE WHEN max_uses = 0 THEN -1 ELSE (max_uses - used_count) END AS remaining_uses
      FROM tokens
      WHERE revoked_at IS NULL AND datetime(expires_at) > datetime('now');
    `);

    repository = new TokenRepository(db);
    cleanupJob = new TokenCleanupJob(repository);
  });

  afterEach(() => {
    db.close();
  });

  describe('run', () => {
    it('should delete expired non-revoked tokens', () => {
      // Create expired non-revoked token
      createExpiredToken('expired-1');

      // Create active token
      repository.create({
        jti: 'active-1',
        public_key: 'key',
        expires_at: new Date(Date.now() + 3600000).toISOString(),
      });

      const deletedCount = cleanupJob.run();

      expect(deletedCount).toBe(1);
      expect(repository.findByJti('expired-1')).toBeNull();
      expect(repository.findByJti('active-1')).not.toBeNull();
    });

    it('should delete old revoked expired tokens (90+ days)', () => {
      // Create token that expired 100 days ago
      createExpiredToken('old-revoked', 100);

      // Revoke it and set revoked_at to 91 days ago
      repository.revoke('old-revoked', 'admin', 'old token');
      db.prepare("UPDATE tokens SET revoked_at = datetime('now', '-91 days') WHERE jti = ?").run(
        'old-revoked'
      );

      const deletedCount = cleanupJob.run();

      expect(deletedCount).toBe(1);
      expect(repository.findByJti('old-revoked')).toBeNull();
    });

    it('should retain recent revoked expired tokens (< 90 days)', () => {
      // Create token that expired 40 days ago
      createExpiredToken('recent-revoked', 40);

      // Revoke it and set revoked_at to 30 days ago
      repository.revoke('recent-revoked', 'admin', 'recent token');
      db.prepare("UPDATE tokens SET revoked_at = datetime('now', '-30 days') WHERE jti = ?").run(
        'recent-revoked'
      );

      const deletedCount = cleanupJob.run();

      expect(deletedCount).toBe(0);
      expect(repository.findByJti('recent-revoked')).not.toBeNull();
    });

    it('should not delete active tokens', () => {
      repository.create({
        jti: 'active-1',
        public_key: 'key',
        expires_at: new Date(Date.now() + 3600000).toISOString(),
      });

      repository.create({
        jti: 'active-2',
        public_key: 'key',
        expires_at: new Date(Date.now() + 7200000).toISOString(),
      });

      const deletedCount = cleanupJob.run();

      expect(deletedCount).toBe(0);
      expect(repository.count()).toBe(2);
    });

    it('should return 0 when no tokens to delete', () => {
      const deletedCount = cleanupJob.run();
      expect(deletedCount).toBe(0);
    });

    it('should handle mixed scenarios correctly', () => {
      // Active token
      repository.create({
        jti: 'active',
        public_key: 'key',
        expires_at: new Date(Date.now() + 3600000).toISOString(),
      });

      // Expired non-revoked (DELETE)
      createExpiredToken('expired-no-revoke');

      // Old revoked expired (DELETE)
      createExpiredToken('old-revoked-expired', 100);
      repository.revoke('old-revoked-expired', 'admin', 'old');
      db.prepare("UPDATE tokens SET revoked_at = datetime('now', '-91 days') WHERE jti = ?").run(
        'old-revoked-expired'
      );

      // Recent revoked expired (KEEP for audit)
      createExpiredToken('recent-revoked-expired', 40);
      repository.revoke('recent-revoked-expired', 'admin', 'recent');
      db.prepare("UPDATE tokens SET revoked_at = datetime('now', '-30 days') WHERE jti = ?").run(
        'recent-revoked-expired'
      );

      const deletedCount = cleanupJob.run();

      expect(deletedCount).toBe(2); // expired-no-revoke + old-revoked-expired
      expect(repository.count()).toBe(2); // active + recent-revoked-expired
      expect(repository.findByJti('active')).not.toBeNull();
      expect(repository.findByJti('recent-revoked-expired')).not.toBeNull();
    });
  });

  describe('getStatistics', () => {
    it('should return accurate statistics', () => {
      // Create different token types
      // 1. Active token
      repository.create({
        jti: 'active',
        public_key: 'key',
        expires_at: new Date(Date.now() + 3600000).toISOString(),
      });

      // 2. Expired non-revoked
      createExpiredToken('expired-no-revoke');

      // 3. Old revoked expired
      createExpiredToken('old-revoked', 100);
      repository.revoke('old-revoked', 'admin', 'old');
      db.prepare("UPDATE tokens SET revoked_at = datetime('now', '-91 days') WHERE jti = ?").run(
        'old-revoked'
      );

      // 4. Recent revoked expired
      createExpiredToken('recent-revoked', 40);
      repository.revoke('recent-revoked', 'admin', 'recent');
      db.prepare("UPDATE tokens SET revoked_at = datetime('now', '-30 days') WHERE jti = ?").run(
        'recent-revoked'
      );

      const stats = cleanupJob.getStatistics();

      expect(stats.totalTokens).toBe(4);
      expect(stats.activeTokens).toBe(1);
      expect(stats.expiredNonRevoked).toBe(1);
      expect(stats.oldRevokedExpired).toBe(1);
      expect(stats.recentRevokedExpired).toBe(1);
      expect(stats.totalDeletionCandidates).toBe(2);
    });

    it('should return zeros for empty database', () => {
      const stats = cleanupJob.getStatistics();

      expect(stats.totalTokens).toBe(0);
      expect(stats.activeTokens).toBe(0);
      expect(stats.expiredNonRevoked).toBe(0);
      expect(stats.oldRevokedExpired).toBe(0);
      expect(stats.recentRevokedExpired).toBe(0);
      expect(stats.totalDeletionCandidates).toBe(0);
    });
  });

  describe('runWithStatistics', () => {
    it('should return statistics before and after cleanup', () => {
      // Create expired token
      createExpiredToken('expired');

      // Create active token
      repository.create({
        jti: 'active',
        public_key: 'key',
        expires_at: new Date(Date.now() + 3600000).toISOString(),
      });

      const result = cleanupJob.runWithStatistics();

      expect(result.deletedCount).toBe(1);
      expect(result.statsBefore.totalTokens).toBe(2);
      expect(result.statsAfter.totalTokens).toBe(1);
      expect(result.statsBefore.expiredNonRevoked).toBe(1);
      expect(result.statsAfter.expiredNonRevoked).toBe(0);
    });

    it('should show no changes when nothing to delete', () => {
      repository.create({
        jti: 'active',
        public_key: 'key',
        expires_at: new Date(Date.now() + 3600000).toISOString(),
      });

      const result = cleanupJob.runWithStatistics();

      expect(result.deletedCount).toBe(0);
      expect(result.statsBefore.totalTokens).toBe(result.statsAfter.totalTokens);
      expect(result.statsBefore.activeTokens).toBe(result.statsAfter.activeTokens);
    });
  });
});
