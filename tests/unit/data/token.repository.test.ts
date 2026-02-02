import Database from 'better-sqlite3';
import { TokenRepository } from '../../../src/data/repositories/token.repository';
import { TokenCreateInput } from '../../../src/data/models/Token.model';

describe('TokenRepository', () => {
  let db: Database.Database;
  let repository: TokenRepository;

  // Helper function to create expired token (bypasses CHECK constraint)
  const createExpiredToken = (jti: string): void => {
    // First create with future date
    repository.create({
      jti,
      public_key: 'key',
      expires_at: new Date(Date.now() + 3600000).toISOString(),
    });

    // Then update both created_at and expires_at to maintain constraint
    db.prepare(`UPDATE tokens SET
      created_at = datetime('now', '-2 hours'),
      expires_at = datetime('now', '-1 hour')
      WHERE jti = ?`).run(jti);
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

      CREATE INDEX idx_tokens_jti ON tokens(jti);
      CREATE INDEX idx_tokens_expires_at ON tokens(expires_at);
      CREATE INDEX idx_tokens_revoked_at ON tokens(revoked_at);

      CREATE VIEW v_active_tokens AS
      SELECT
        id, jti, created_at, expires_at, max_uses, used_count,
        CASE WHEN max_uses = 0 THEN -1 ELSE (max_uses - used_count) END AS remaining_uses
      FROM tokens
      WHERE revoked_at IS NULL AND datetime(expires_at) > datetime('now');
    `);

    repository = new TokenRepository(db);
  });

  afterEach(() => {
    db.close();
  });

  describe('create', () => {
    it('should create a token successfully', () => {
      const input: TokenCreateInput = {
        jti: 'test-jti-123',
        public_key: '-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----',
        expires_at: new Date(Date.now() + 3600000).toISOString(),
        max_uses: 10,
        metadata: '{"purpose": "test"}',
      };

      const token = repository.create(input);

      expect(token).toBeDefined();
      expect(token.id).toBeGreaterThan(0);
      expect(token.jti).toBe(input.jti);
      expect(token.public_key).toBe(input.public_key);
      expect(token.max_uses).toBe(10);
      expect(token.used_count).toBe(0);
      expect(token.revoked_at).toBeNull();
    });

    it('should create token with default values', () => {
      const input: TokenCreateInput = {
        jti: 'test-jti-456',
        public_key: '-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----',
        expires_at: new Date(Date.now() + 3600000).toISOString(),
      };

      const token = repository.create(input);

      expect(token.max_uses).toBe(0);
      expect(token.metadata).toBeNull();
    });

    it('should throw error on duplicate jti', () => {
      const input: TokenCreateInput = {
        jti: 'duplicate-jti',
        public_key: 'test-key',
        expires_at: new Date(Date.now() + 3600000).toISOString(),
      };

      repository.create(input);

      expect(() => repository.create(input)).toThrow();
    });
  });

  describe('findByJti', () => {
    it('should find token by jti', () => {
      const input: TokenCreateInput = {
        jti: 'find-me',
        public_key: 'test-key',
        expires_at: new Date(Date.now() + 3600000).toISOString(),
      };

      repository.create(input);
      const found = repository.findByJti('find-me');

      expect(found).not.toBeNull();
      expect(found?.jti).toBe('find-me');
    });

    it('should return null for non-existent jti', () => {
      const found = repository.findByJti('non-existent');
      expect(found).toBeNull();
    });
  });

  describe('findAll', () => {
    it('should return all tokens', () => {
      repository.create({
        jti: 'token-1',
        public_key: 'key-1',
        expires_at: new Date(Date.now() + 3600000).toISOString(),
      });

      repository.create({
        jti: 'token-2',
        public_key: 'key-2',
        expires_at: new Date(Date.now() + 3600000).toISOString(),
      });

      const tokens = repository.findAll();
      expect(tokens).toHaveLength(2);
    });

    it('should return empty array when no tokens', () => {
      const tokens = repository.findAll();
      expect(tokens).toEqual([]);
    });
  });

  describe('findActive', () => {
    it('should return only active tokens', () => {
      // Create active token
      repository.create({
        jti: 'active-1',
        public_key: 'key-1',
        expires_at: new Date(Date.now() + 3600000).toISOString(),
      });

      // Create expired token
      createExpiredToken('expired-1');

      // Create revoked token
      const token3 = repository.create({
        jti: 'revoked-1',
        public_key: 'key-3',
        expires_at: new Date(Date.now() + 3600000).toISOString(),
      });
      repository.revoke(token3.jti, 'test', 'testing');

      const activeTokens = repository.findActive();
      expect(activeTokens).toHaveLength(1);
      expect(activeTokens[0]!.jti).toBe('active-1');
    });

    it('should calculate remaining_uses correctly', () => {
      repository.create({
        jti: 'limited-token',
        public_key: 'key',
        expires_at: new Date(Date.now() + 3600000).toISOString(),
        max_uses: 5,
      });

      const activeTokens = repository.findActive();
      expect(activeTokens[0]!.remaining_uses).toBe(5);
    });

    it('should return -1 for unlimited tokens', () => {
      repository.create({
        jti: 'unlimited-token',
        public_key: 'key',
        expires_at: new Date(Date.now() + 3600000).toISOString(),
        max_uses: 0,
      });

      const activeTokens = repository.findActive();
      expect(activeTokens[0]!.remaining_uses).toBe(-1);
    });
  });

  describe('incrementUsage', () => {
    it('should increment usage count', () => {
      repository.create({
        jti: 'usage-test',
        public_key: 'key',
        expires_at: new Date(Date.now() + 3600000).toISOString(),
        max_uses: 10,
      });

      repository.incrementUsage('usage-test');

      const token = repository.findByJti('usage-test');
      expect(token?.used_count).toBe(1);

      repository.incrementUsage('usage-test');
      const token2 = repository.findByJti('usage-test');
      expect(token2?.used_count).toBe(2);
    });

    it('should throw error when usage limit exceeded', () => {
      repository.create({
        jti: 'limited-usage',
        public_key: 'key',
        expires_at: new Date(Date.now() + 3600000).toISOString(),
        max_uses: 2,
      });

      repository.incrementUsage('limited-usage');
      repository.incrementUsage('limited-usage');

      expect(() => repository.incrementUsage('limited-usage')).toThrow();
    });

    it('should throw error for expired token', () => {
      createExpiredToken('expired-usage');
      expect(() => repository.incrementUsage('expired-usage')).toThrow();
    });

    it('should throw error for revoked token', () => {
      repository.create({
        jti: 'revoked-usage',
        public_key: 'key',
        expires_at: new Date(Date.now() + 3600000).toISOString(),
      });

      repository.revoke('revoked-usage', 'test', 'testing');

      expect(() => repository.incrementUsage('revoked-usage')).toThrow();
    });

    it('should allow unlimited usage when max_uses is 0', () => {
      repository.create({
        jti: 'unlimited-usage',
        public_key: 'key',
        expires_at: new Date(Date.now() + 3600000).toISOString(),
        max_uses: 0,
      });

      for (let i = 0; i < 100; i++) {
        repository.incrementUsage('unlimited-usage');
      }

      const token = repository.findByJti('unlimited-usage');
      expect(token?.used_count).toBe(100);
    });
  });

  describe('revoke', () => {
    it('should revoke token successfully', () => {
      repository.create({
        jti: 'revoke-test',
        public_key: 'key',
        expires_at: new Date(Date.now() + 3600000).toISOString(),
      });

      repository.revoke('revoke-test', 'admin', 'security incident');

      const token = repository.findByJti('revoke-test');
      expect(token?.revoked_at).not.toBeNull();
      expect(token?.revoked_by).toBe('admin');
      expect(token?.revoked_reason).toBe('security incident');
    });

    it('should throw error when revoking already revoked token', () => {
      repository.create({
        jti: 'already-revoked',
        public_key: 'key',
        expires_at: new Date(Date.now() + 3600000).toISOString(),
      });

      repository.revoke('already-revoked', 'admin', 'first revocation');

      expect(() => repository.revoke('already-revoked', 'admin', 'second revocation')).toThrow();
    });

    it('should throw error for non-existent token', () => {
      expect(() => repository.revoke('non-existent', 'admin', 'test')).toThrow();
    });
  });

  describe('deleteExpired', () => {
    it('should delete expired tokens', () => {
      // Create expired token
      createExpiredToken('expired-delete');

      // Create active token
      repository.create({
        jti: 'active-delete',
        public_key: 'key',
        expires_at: new Date(Date.now() + 3600000).toISOString(),
      });

      const deletedCount = repository.deleteExpired();

      expect(deletedCount).toBe(1);
      expect(repository.findByJti('expired-delete')).toBeNull();
      expect(repository.findByJti('active-delete')).not.toBeNull();
    });

    it('should return 0 when no expired tokens', () => {
      repository.create({
        jti: 'active-only',
        public_key: 'key',
        expires_at: new Date(Date.now() + 3600000).toISOString(),
      });

      const deletedCount = repository.deleteExpired();
      expect(deletedCount).toBe(0);
    });
  });

  describe('count', () => {
    it('should return total token count', () => {
      expect(repository.count()).toBe(0);

      repository.create({
        jti: 'count-1',
        public_key: 'key',
        expires_at: new Date(Date.now() + 3600000).toISOString(),
      });

      expect(repository.count()).toBe(1);

      repository.create({
        jti: 'count-2',
        public_key: 'key',
        expires_at: new Date(Date.now() + 3600000).toISOString(),
      });

      expect(repository.count()).toBe(2);
    });
  });

  describe('countActive', () => {
    it('should return active token count', () => {
      // Create active tokens
      repository.create({
        jti: 'active-count-1',
        public_key: 'key',
        expires_at: new Date(Date.now() + 3600000).toISOString(),
      });

      repository.create({
        jti: 'active-count-2',
        public_key: 'key',
        expires_at: new Date(Date.now() + 3600000).toISOString(),
      });

      // Create expired token
      createExpiredToken('expired-count');

      expect(repository.countActive()).toBe(2);
    });

    it('should return 0 when no active tokens', () => {
      expect(repository.countActive()).toBe(0);
    });
  });
});
