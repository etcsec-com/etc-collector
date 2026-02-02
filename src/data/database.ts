import Database from 'better-sqlite3';
import { mkdirSync, existsSync } from 'fs';
import { dirname } from 'path';
import { logInfo, logError } from '../utils/logger';

/**
 * SQLite Database Connection Manager
 * Singleton pattern for database access
 */
export class DatabaseManager {
  private static instance: DatabaseManager;
  private db: Database.Database | null = null;
  private dbPath: string | null = null;

  private constructor() {}

  static getInstance(): DatabaseManager {
    if (!DatabaseManager.instance) {
      DatabaseManager.instance = new DatabaseManager();
    }
    return DatabaseManager.instance;
  }

  connect(dbPath: string): Database.Database {
    if (this.db) {
      return this.db;
    }

    try {
      // Create parent directory if not exists
      const dir = dirname(dbPath);
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
        logInfo('Created database directory', { path: dir });
      }

      // Connect to database
      this.db = new Database(dbPath);
      this.dbPath = dbPath;

      // Configure pragmas for performance and safety
      this.db.pragma('journal_mode = WAL'); // Write-Ahead Logging
      this.db.pragma('synchronous = NORMAL'); // Balance safety/performance
      this.db.pragma('foreign_keys = ON'); // Enable foreign key constraints
      this.db.pragma('busy_timeout = 5000'); // 5 second timeout on locks

      logInfo('Database connected successfully', {
        path: dbPath,
        journalMode: this.db.pragma('journal_mode', { simple: true }),
      });

      return this.db;
    } catch (error) {
      logError('Failed to connect to database', error as Error, { path: dbPath });
      throw error;
    }
  }

  getDatabase(): Database.Database {
    if (!this.db) {
      throw new Error('Database not connected. Call connect() first.');
    }
    return this.db;
  }

  close(): void {
    if (this.db) {
      logInfo('Closing database connection', { path: this.dbPath });
      this.db.close();
      this.db = null;
      this.dbPath = null;
    }
  }

  isConnected(): boolean {
    return this.db !== null;
  }
}
