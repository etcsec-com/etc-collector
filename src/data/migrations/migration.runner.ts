import { readFileSync, readdirSync } from 'fs';
import { join } from 'path';
import Database from 'better-sqlite3';
import { logInfo, logError } from '../../utils/logger';

/**
 * Migration Runner
 * Executes SQL migration files sequentially with version tracking
 */
export class MigrationRunner {
  constructor(private db: Database.Database) {}

  async run(): Promise<void> {
    try {
      logInfo('Starting database migrations');

      // Create migrations tracking table
      this.createMigrationsTable();

      // Get current version
      const currentVersion = this.getCurrentVersion();
      logInfo('Current migration version', { version: currentVersion });

      // Find all migration files
      const migrations = this.findMigrationFiles();

      // Apply pending migrations
      let appliedCount = 0;
      for (const migration of migrations) {
        if (migration.version > currentVersion) {
          this.applyMigration(migration);
          appliedCount++;
        }
      }

      if (appliedCount === 0) {
        logInfo('No pending migrations');
      } else {
        logInfo('Migrations completed', { appliedCount });
      }
    } catch (error) {
      logError('Migration failed', error as Error);
      throw error;
    }
  }

  private createMigrationsTable(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS migrations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        version INTEGER UNIQUE NOT NULL,
        name TEXT NOT NULL,
        applied_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
    `);
  }

  private getCurrentVersion(): number {
    const result = this.db
      .prepare('SELECT COALESCE(MAX(version), 0) as version FROM migrations')
      .get() as { version: number };
    return result.version;
  }

  private findMigrationFiles(): Array<{ version: number; name: string; path: string }> {
    const migrationsDir = __dirname;
    const files = readdirSync(migrationsDir).filter((f) => f.endsWith('.sql'));

    return files
      .map((file) => ({
        version: this.getMigrationVersion(file),
        name: file,
        path: join(migrationsDir, file),
      }))
      .sort((a, b) => a.version - b.version);
  }

  private getMigrationVersion(filename: string): number {
    const match = filename.match(/^(\d+)_/);
    if (!match || !match[1]) {
      throw new Error(`Invalid migration filename: ${filename}`);
    }
    return parseInt(match[1], 10);
  }

  private applyMigration(migration: { version: number; name: string; path: string }): void {
    logInfo('Applying migration', { name: migration.name, version: migration.version });

    // Wrap in transaction for atomicity
    const apply = this.db.transaction(() => {
      try {
        // Read and execute SQL
        const sql = readFileSync(migration.path, 'utf-8');
        this.db.exec(sql);

        // Record migration
        this.db
          .prepare('INSERT INTO migrations (version, name) VALUES (?, ?)')
          .run(migration.version, migration.name);

        logInfo('Migration applied successfully', { name: migration.name });
      } catch (error) {
        logError('Migration failed', error as Error, { name: migration.name });
        throw error;
      }
    });

    apply();
  }

  /**
   * Static helper for running migrations from config
   */
  static async runMigrations(dbPath: string): Promise<void> {
    const Database = (await import('better-sqlite3')).default;
    const db = new Database(dbPath);

    try {
      const runner = new MigrationRunner(db);
      await runner.run();
    } finally {
      db.close();
    }
  }
}
