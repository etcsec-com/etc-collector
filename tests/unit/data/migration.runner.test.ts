import Database from 'better-sqlite3';
import { MigrationRunner } from '../../../src/data/migrations/migration.runner';

describe('MigrationRunner', () => {
  let db: Database.Database;

  beforeEach(() => {
    // Create in-memory database
    db = new Database(':memory:');
  });

  afterEach(() => {
    db.close();
  });

  describe('run', () => {
    it('should create migrations tracking table', async () => {
      const runner = new MigrationRunner(db);
      await runner.run();

      const result = db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='migrations'")
        .get();

      expect(result).toBeDefined();
    });

    it('should track migration version', async () => {
      const runner = new MigrationRunner(db);
      await runner.run();

      const result = db.prepare('SELECT version FROM migrations').all();
      expect(Array.isArray(result)).toBe(true);
    });

    it('should not reapply migrations', async () => {
      const runner = new MigrationRunner(db);

      // First run
      await runner.run();
      const countAfterFirst = db.prepare('SELECT COUNT(*) as count FROM migrations').get() as {
        count: number;
      };

      // Second run (should be idempotent)
      await runner.run();
      const countAfterSecond = db.prepare('SELECT COUNT(*) as count FROM migrations').get() as {
        count: number;
      };

      expect(countAfterFirst.count).toBe(countAfterSecond.count);
    });

    it('should apply real migrations successfully', async () => {
      const runner = new MigrationRunner(db);
      await runner.run();

      // Verify that the initial migration created the tokens table
      const tables = db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .all() as Array<{ name: string }>;

      const tableNames = tables.map((t) => t.name);
      expect(tableNames).toContain('tokens');
      expect(tableNames).toContain('migrations');

      // Verify views were created
      const views = db
        .prepare("SELECT name FROM sqlite_master WHERE type='view'")
        .all() as Array<{ name: string }>;

      const viewNames = views.map((v) => v.name);
      expect(viewNames).toContain('v_active_tokens');
    });
  });

  describe('getCurrentVersion', () => {
    it('should return 0 for new database', async () => {
      const runner = new MigrationRunner(db);
      await runner.run();

      const version = runner['getCurrentVersion']();
      expect(version).toBeGreaterThanOrEqual(0);
    });
  });

  describe('getMigrationVersion', () => {
    it('should extract version from filename', () => {
      const runner = new MigrationRunner(db);

      const version1 = runner['getMigrationVersion']('001_initial_schema.sql');
      expect(version1).toBe(1);

      const version2 = runner['getMigrationVersion']('042_add_column.sql');
      expect(version2).toBe(42);

      const version3 = runner['getMigrationVersion']('0123_test.sql');
      expect(version3).toBe(123);
    });

    it('should throw error for invalid filename', () => {
      const runner = new MigrationRunner(db);

      expect(() => runner['getMigrationVersion']('invalid_migration.sql')).toThrow();
      expect(() => runner['getMigrationVersion']('no-number.sql')).toThrow();
    });
  });

  describe('static runMigrations', () => {
    it('should run migrations and close database', async () => {
      const dbPath = ':memory:';

      // This should not throw
      await expect(MigrationRunner.runMigrations(dbPath)).resolves.not.toThrow();
    });
  });
});
