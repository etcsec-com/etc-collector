/**
 * Credential Store Service
 * Persists enrollment credentials locally for the collector
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import * as os from 'os';
import { logInfo, logError, logDebug } from '../../utils/logger';
import { CollectorCredentials } from '../../types/saas.types';

const CREDENTIALS_FILE = 'collector-credentials.enc';
const ENCRYPTION_ALGORITHM = 'aes-256-gcm';

export class CredentialStoreService {
  private readonly dataDir: string;
  private readonly credentialsPath: string;

  constructor(dataDir?: string) {
    // Default to ./data directory
    this.dataDir = dataDir || path.join(process.cwd(), 'data');
    this.credentialsPath = path.join(this.dataDir, CREDENTIALS_FILE);
  }

  /**
   * Get machine-specific encryption key
   * Uses hardware identifiers for basic protection
   */
  private getEncryptionKey(): Buffer {
    // Combine hostname, platform, and arch for a machine-specific key
    const machineId = [
      process.env['HOSTNAME'] || os.hostname(),
      process.platform,
      process.arch,
      // Add process user for additional entropy
      process.env['USER'] || process.env['USERNAME'] || 'default',
    ].join(':');

    // Derive a 256-bit key from the machine ID
    return crypto.scryptSync(machineId, 'etc-collector-salt-v1', 32);
  }

  /**
   * Encrypt and save credentials
   */
  async save(credentials: CollectorCredentials): Promise<void> {
    logInfo('Saving collector credentials');

    try {
      // Ensure data directory exists
      if (!fs.existsSync(this.dataDir)) {
        fs.mkdirSync(this.dataDir, { recursive: true });
      }

      const key = this.getEncryptionKey();
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, key, iv);

      const plaintext = JSON.stringify(credentials);
      let encrypted = cipher.update(plaintext, 'utf8', 'hex');
      encrypted += cipher.final('hex');

      const authTag = cipher.getAuthTag();

      // Store IV + AuthTag + EncryptedData
      const data = {
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex'),
        data: encrypted,
        version: 1,
      };

      fs.writeFileSync(this.credentialsPath, JSON.stringify(data, null, 2), {
        mode: 0o600, // Owner read/write only
      });

      logInfo('Credentials saved successfully', {
        path: this.credentialsPath,
        collectorId: credentials.collectorId,
      });
    } catch (error) {
      logError('Failed to save credentials', error as Error);
      throw new Error(`Failed to save credentials: ${(error as Error).message}`);
    }
  }

  /**
   * Load and decrypt credentials
   */
  async load(): Promise<CollectorCredentials | null> {
    logDebug('Loading collector credentials');

    try {
      if (!fs.existsSync(this.credentialsPath)) {
        logDebug('No credentials file found');
        return null;
      }

      const fileContent = fs.readFileSync(this.credentialsPath, 'utf8');
      const data = JSON.parse(fileContent);

      const key = this.getEncryptionKey();
      const iv = Buffer.from(data.iv, 'hex');
      const authTag = Buffer.from(data.authTag, 'hex');

      const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, key, iv);
      decipher.setAuthTag(authTag);

      let decrypted = decipher.update(data.data, 'hex', 'utf8');
      decrypted += decipher.final('utf8');

      const credentials = JSON.parse(decrypted) as CollectorCredentials;

      logInfo('Credentials loaded successfully', {
        collectorId: credentials.collectorId,
        enrolledAt: credentials.enrolledAt,
      });

      return credentials;
    } catch (error) {
      logError('Failed to load credentials', error as Error);

      // If decryption fails (different machine or corrupted file), delete it
      if ((error as Error).message.includes('Unsupported state') ||
          (error as Error).message.includes('bad decrypt')) {
        logError('Credentials file corrupted or from different machine, removing...');
        this.delete();
      }
      return null;
    }
  }

  /**
   * Check if credentials exist
   */
  exists(): boolean {
    return fs.existsSync(this.credentialsPath);
  }

  /**
   * Delete credentials (for unenrollment)
   */
  delete(): void {
    logInfo('Deleting collector credentials');

    try {
      if (fs.existsSync(this.credentialsPath)) {
        fs.unlinkSync(this.credentialsPath);
        logInfo('Credentials deleted successfully');
      }
    } catch (error) {
      logError('Failed to delete credentials', error as Error);
    }
  }

  /**
   * Get credentials path (for diagnostics)
   */
  getPath(): string {
    return this.credentialsPath;
  }
}
