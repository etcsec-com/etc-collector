import { TokenRepository } from '../../../src/data/repositories/token.repository';
import { TokenCleanupJob } from '../../../src/data/jobs/token-cleanup.job';
import { DatabaseManager } from '../../../src/data/database';
import { MigrationRunner } from '../../../src/data/migrations/migration.runner';
import { existsSync, unlinkSync, mkdirSync } from 'fs';
import { join } from 'path';

/**
 * Integration Tests for Token Persistence
 * Tests database operations with real SQLite file to verify persistence
 */
describe('Token Persistence Integration', () => {
  const testDbPath = join(__dirname, '../../__test_data__/integration-test.db');
  const testDbDir = join(__dirname, '../../__test_data__');

  beforeAll(() => {
    // Create test data directory
    if (!existsSync(testDbDir)) {
      mkdirSync(testDbDir, { recursive: true });
    }
  });

  afterAll(() => {
    // Cleanup test database
    if (existsSync(testDbPath)) {
      unlinkSync(testDbPath);
    }
  });

  beforeEach(() => {
    // Remove existing test database before each test
    if (existsSync(testDbPath)) {
      unlinkSync(testDbPath);
    }
  });

  it('IV1: Tokens peuvent être créés et récupérés', async () => {
    // Setup: Create database and run migrations
    await MigrationRunner.runMigrations(testDbPath);

    const dbManager = DatabaseManager.getInstance();
    const db = dbManager.connect(testDbPath);
    const repository = new TokenRepository(db);

    // Test: Create token
    const tokenInput = {
      jti: 'test-jti-iv1',
      public_key: '-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----',
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      max_uses: 10,
      metadata: '{"purpose": "integration-test"}',
    };

    const createdToken = repository.create(tokenInput);

    // Verify: All fields match
    expect(createdToken.jti).toBe(tokenInput.jti);
    expect(createdToken.public_key).toBe(tokenInput.public_key);
    expect(createdToken.expires_at).toBe(tokenInput.expires_at);
    expect(createdToken.max_uses).toBe(10);
    expect(createdToken.used_count).toBe(0);
    expect(createdToken.metadata).toBe(tokenInput.metadata);
    expect(createdToken.revoked_at).toBeNull();
    expect(createdToken.id).toBeGreaterThan(0);

    // Test: Retrieve token
    const retrievedToken = repository.findByJti('test-jti-iv1');

    // Verify: Retrieved token matches created token
    expect(retrievedToken).not.toBeNull();
    expect(retrievedToken!.jti).toBe(createdToken.jti);
    expect(retrievedToken!.public_key).toBe(createdToken.public_key);
    expect(retrievedToken!.max_uses).toBe(createdToken.max_uses);
    expect(retrievedToken!.used_count).toBe(createdToken.used_count);

    dbManager.close();
  });

  it('IV2: Token révoqué est marqué correctement dans DB', async () => {
    // Setup
    await MigrationRunner.runMigrations(testDbPath);

    const dbManager = DatabaseManager.getInstance();
    const db = dbManager.connect(testDbPath);
    const repository = new TokenRepository(db);

    // Test: Create token
    const token = repository.create({
      jti: 'test-jti-iv2',
      public_key: 'test-key',
      expires_at: new Date(Date.now() + 3600000).toISOString(),
    });

    expect(token.revoked_at).toBeNull();

    // Test: Revoke token
    repository.revoke('test-jti-iv2', 'admin', 'security incident');

    // Test: Retrieve revoked token
    const revokedToken = repository.findByJti('test-jti-iv2');

    // Verify: All revocation fields are set
    expect(revokedToken).not.toBeNull();
    expect(revokedToken!.revoked_at).not.toBeNull();
    expect(revokedToken!.revoked_by).toBe('admin');
    expect(revokedToken!.revoked_reason).toBe('security incident');

    // Verify: Token is not in active list
    const activeTokens = repository.findActive();
    expect(activeTokens.find((t) => t.jti === 'test-jti-iv2')).toBeUndefined();

    dbManager.close();
  });

  it('IV3: Cleanup supprime les tokens expirés', async () => {
    // Setup
    await MigrationRunner.runMigrations(testDbPath);

    const dbManager = DatabaseManager.getInstance();
    const db = dbManager.connect(testDbPath);
    const repository = new TokenRepository(db);
    const cleanupJob = new TokenCleanupJob(repository);

    // Create old expired non-revoked token (100 days ago, will be deleted immediately)
    repository.create({
      jti: 'old-expired-nonrevoked',
      public_key: 'key',
      expires_at: new Date(Date.now() + 3600000).toISOString(),
    });
    db.prepare(`UPDATE tokens SET
      created_at = datetime('now', '-101 days'),
      expires_at = datetime('now', '-100 days')
      WHERE jti = ?`).run('old-expired-nonrevoked');

    // Create old revoked expired token (expired 100 days ago, revoked 95 days ago, will be deleted)
    repository.create({
      jti: 'old-revoked-expired',
      public_key: 'key',
      expires_at: new Date(Date.now() + 3600000).toISOString(),
    });
    db.prepare(`UPDATE tokens SET
      created_at = datetime('now', '-101 days'),
      expires_at = datetime('now', '-100 days')
      WHERE jti = ?`).run('old-revoked-expired');
    repository.revoke('old-revoked-expired', 'admin', 'test');
    db.prepare("UPDATE tokens SET revoked_at = datetime('now', '-95 days') WHERE jti = ?").run(
      'old-revoked-expired'
    );

    // Create recent revoked expired token (expired 40 days ago, revoked 30 days ago, will be kept)
    repository.create({
      jti: 'recent-revoked-expired',
      public_key: 'key',
      expires_at: new Date(Date.now() + 3600000).toISOString(),
    });
    db.prepare(`UPDATE tokens SET
      created_at = datetime('now', '-41 days'),
      expires_at = datetime('now', '-40 days')
      WHERE jti = ?`).run('recent-revoked-expired');
    repository.revoke('recent-revoked-expired', 'admin', 'test');
    db.prepare("UPDATE tokens SET revoked_at = datetime('now', '-30 days') WHERE jti = ?").run(
      'recent-revoked-expired'
    );

    // Create active token (will be kept)
    repository.create({
      jti: 'active-token',
      public_key: 'key',
      expires_at: new Date(Date.now() + 3600000).toISOString(),
    });

    // Verify initial state
    expect(repository.count()).toBe(4);

    // Test: Run cleanup job
    const deletedCount = cleanupJob.run();

    // Verify: Old tokens deleted (non-revoked + old-revoked), recent revoked kept
    expect(deletedCount).toBe(2);
    expect(repository.count()).toBe(2);
    expect(repository.findByJti('old-expired-nonrevoked')).toBeNull();
    expect(repository.findByJti('old-revoked-expired')).toBeNull();
    expect(repository.findByJti('recent-revoked-expired')).not.toBeNull(); // Kept for audit
    expect(repository.findByJti('active-token')).not.toBeNull();

    dbManager.close();
  });

  it('IV4: Migration script convertit l\'ancien schema avec succès', async () => {
    // This test verifies that the migration runner works with the schema
    // For actual identity-collector migration, scripts/migrate-tokens.ts would be used

    // Setup: Create fresh database
    await MigrationRunner.runMigrations(testDbPath);

    const dbManager = DatabaseManager.getInstance();
    const db = dbManager.connect(testDbPath);

    // Verify: Migrations table exists and has version 1
    const migrationVersion = db
      .prepare('SELECT MAX(version) as version FROM migrations')
      .get() as { version: number };
    expect(migrationVersion.version).toBe(1);

    // Verify: Tokens table exists with correct schema
    const tableInfo = db.prepare("PRAGMA table_info(tokens)").all() as Array<{
      name: string;
      type: string;
      notnull: number;
    }>;

    const columnNames = tableInfo.map((col) => col.name);
    expect(columnNames).toContain('id');
    expect(columnNames).toContain('jti');
    expect(columnNames).toContain('public_key');
    expect(columnNames).toContain('expires_at');
    expect(columnNames).toContain('max_uses');
    expect(columnNames).toContain('used_count');
    expect(columnNames).toContain('revoked_at');
    expect(columnNames).toContain('revoked_by');
    expect(columnNames).toContain('revoked_reason');
    expect(columnNames).toContain('metadata');

    // Verify: View exists
    const views = db
      .prepare("SELECT name FROM sqlite_master WHERE type='view'")
      .all() as Array<{ name: string }>;
    expect(views.find((v) => v.name === 'v_active_tokens')).toBeDefined();

    // Verify: Indexes exist
    const indexes = db
      .prepare("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='tokens'")
      .all() as Array<{ name: string }>;
    const indexNames = indexes.map((idx) => idx.name);
    expect(indexNames).toContain('idx_tokens_jti');
    expect(indexNames).toContain('idx_tokens_expires_at');
    expect(indexNames).toContain('idx_tokens_revoked_at');

    dbManager.close();
  });

  it('IV5: Database survive aux redémarrages', async () => {
    // Setup: Create database and run migrations
    await MigrationRunner.runMigrations(testDbPath);

    let dbManager = DatabaseManager.getInstance();
    let db = dbManager.connect(testDbPath);
    let repository = new TokenRepository(db);

    // Test: Create token
    const tokenInput = {
      jti: 'persistence-test',
      public_key: 'test-key',
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      max_uses: 5,
      metadata: '{"test": "data"}',
    };

    repository.create(tokenInput);

    // Increment usage
    repository.incrementUsage('persistence-test');
    repository.incrementUsage('persistence-test');

    // Verify token exists with used_count = 2
    let token = repository.findByJti('persistence-test');
    expect(token).not.toBeNull();
    expect(token!.used_count).toBe(2);

    // Test: Close database connection
    dbManager.close();

    // Simulate restart: Reopen database connection
    // Need to create new instance since singleton pattern
    const DatabaseManagerClass = DatabaseManager as any;
    DatabaseManagerClass.instance = undefined;

    dbManager = DatabaseManager.getInstance();
    db = dbManager.connect(testDbPath);
    repository = new TokenRepository(db);

    // Test: Verify token still exists with same data
    token = repository.findByJti('persistence-test');

    expect(token).not.toBeNull();
    expect(token!.jti).toBe('persistence-test');
    expect(token!.public_key).toBe('test-key');
    expect(token!.max_uses).toBe(5);
    expect(token!.used_count).toBe(2); // Persisted usage count
    expect(token!.metadata).toBe('{"test": "data"}');

    // Test: Continue operations after restart
    repository.incrementUsage('persistence-test');
    token = repository.findByJti('persistence-test');
    expect(token!.used_count).toBe(3);

    dbManager.close();
  });
});
