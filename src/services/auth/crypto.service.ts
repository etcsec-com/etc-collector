import crypto from 'crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from 'fs';
import { dirname } from 'path';
import type { Logger } from 'winston';
import { logger } from '../../utils/logger';

/**
 * CryptoService
 *
 * Manages RSA key pairs for RS256 JWT signatures.
 *
 * Features:
 * - Generates 2048-bit RSA key pairs
 * - Persists keys to filesystem (PKCS#8 private, SPKI public)
 * - Loads existing keys or auto-generates on first use
 * - Sets secure file permissions (600 for private, 644 for public)
 *
 * Task 1: RS256 Key Management (Story 1.4)
 *
 * Integration Verifications:
 * - IV1: Auto-generates key pair on first startup
 * - IV2: Loads existing keys from filesystem
 * - IV3: Private key has 600 permissions
 * - IV4: Public key has 644 permissions
 * - IV5: Keys persist across server restarts
 */

export interface KeyPair {
  privateKey: string;
  publicKey: string;
}

export class CryptoService {
  private privateKey: string | null = null;
  private publicKey: string | null = null;
  private logger: Logger;

  constructor(
    private privateKeyPath: string,
    private publicKeyPath: string
  ) {
    this.logger = logger;
  }

  /**
   * Generate a new RSA key pair
   *
   * Specification:
   * - Algorithm: RSA
   * - Key size: 2048 bits
   * - Private key format: PKCS#8 PEM
   * - Public key format: SPKI PEM
   *
   * @returns KeyPair with private and public keys in PEM format
   */
  generateKeyPair(): KeyPair {
    this.logger.info('Generating new RSA key pair (2048-bit)');

    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
      },
    });

    this.logger.info('RSA key pair generated successfully');
    return { privateKey, publicKey };
  }

  /**
   * Load existing keys from filesystem or generate new ones
   *
   * Flow:
   * 1. Check if both key files exist
   * 2. If yes: load from files and cache in memory
   * 3. If no: generate new key pair, save to files, cache in memory
   *
   * File permissions:
   * - Private key: 600 (owner read/write only)
   * - Public key: 644 (owner read/write, others read)
   *
   * @throws Error if key loading or generation fails
   */
  async loadOrGenerateKeys(): Promise<void> {
    const privateKeyExists = existsSync(this.privateKeyPath);
    const publicKeyExists = existsSync(this.publicKeyPath);

    if (privateKeyExists && publicKeyExists) {
      // Load existing keys
      this.logger.info('Loading existing RSA keys from filesystem', {
        privateKeyPath: this.privateKeyPath,
        publicKeyPath: this.publicKeyPath,
      });

      try {
        this.privateKey = readFileSync(this.privateKeyPath, 'utf-8');
        this.publicKey = readFileSync(this.publicKeyPath, 'utf-8');

        // Validate that keys are in correct PEM format
        this.validateKeyFormat(this.privateKey, 'PRIVATE KEY');
        this.validateKeyFormat(this.publicKey, 'PUBLIC KEY');

        this.logger.info('RSA keys loaded successfully from filesystem');
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        this.logger.error('Failed to load RSA keys from filesystem', { error: message });
        throw new Error(`Failed to load RSA keys: ${message}`);
      }
    } else {
      // Generate and save new keys
      if (privateKeyExists !== publicKeyExists) {
        this.logger.warn('Only one key file exists, regenerating both', {
          privateKeyExists,
          publicKeyExists,
        });
      } else {
        this.logger.info('No existing keys found, generating new RSA key pair');
      }

      try {
        const keyPair = this.generateKeyPair();
        this.privateKey = keyPair.privateKey;
        this.publicKey = keyPair.publicKey;

        this.saveKeys(keyPair);
        this.logger.info('RSA keys generated and saved successfully');
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        this.logger.error('Failed to generate and save RSA keys', { error: message });
        throw new Error(`Failed to generate RSA keys: ${message}`);
      }
    }
  }

  /**
   * Get the cached private key
   *
   * @returns Private key in PEM format
   * @throws Error if keys haven't been loaded yet
   */
  getPrivateKey(): string {
    if (!this.privateKey) {
      throw new Error('Keys not loaded. Call loadOrGenerateKeys() first.');
    }
    return this.privateKey;
  }

  /**
   * Get the cached public key
   *
   * @returns Public key in PEM format
   * @throws Error if keys haven't been loaded yet
   */
  getPublicKey(): string {
    if (!this.publicKey) {
      throw new Error('Keys not loaded. Call loadOrGenerateKeys() first.');
    }
    return this.publicKey;
  }

  /**
   * Save key pair to filesystem with secure permissions
   *
   * Security:
   * - Creates parent directories if needed
   * - Sets private key to 600 (owner read/write only)
   * - Sets public key to 644 (owner read/write, others read)
   *
   * @param keyPair The key pair to save
   * @throws Error if file operations fail
   */
  private saveKeys(keyPair: KeyPair): void {
    try {
      // Ensure parent directories exist
      const privateKeyDir = dirname(this.privateKeyPath);
      const publicKeyDir = dirname(this.publicKeyPath);

      if (!existsSync(privateKeyDir)) {
        mkdirSync(privateKeyDir, { recursive: true });
        this.logger.debug('Created directory for private key', { path: privateKeyDir });
      }

      if (!existsSync(publicKeyDir)) {
        mkdirSync(publicKeyDir, { recursive: true });
        this.logger.debug('Created directory for public key', { path: publicKeyDir });
      }

      // Write private key with restrictive permissions
      writeFileSync(this.privateKeyPath, keyPair.privateKey, { mode: 0o600 });
      chmodSync(this.privateKeyPath, 0o600);
      this.logger.debug('Private key saved', {
        path: this.privateKeyPath,
        permissions: '600',
      });

      // Write public key with standard permissions
      writeFileSync(this.publicKeyPath, keyPair.publicKey, { mode: 0o644 });
      chmodSync(this.publicKeyPath, 0o644);
      this.logger.debug('Public key saved', {
        path: this.publicKeyPath,
        permissions: '644',
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      this.logger.error('Failed to save keys to filesystem', { error: message });
      throw new Error(`Failed to save keys: ${message}`);
    }
  }

  /**
   * Validate that a key string is in correct PEM format
   *
   * @param key The key string to validate
   * @param keyType Expected key type ('PRIVATE KEY' or 'PUBLIC KEY')
   * @throws Error if key format is invalid
   */
  private validateKeyFormat(key: string, keyType: string): void {
    const beginMarker = `-----BEGIN ${keyType}-----`;
    const endMarker = `-----END ${keyType}-----`;

    if (!key.includes(beginMarker) || !key.includes(endMarker)) {
      throw new Error(`Invalid ${keyType} format: missing PEM markers`);
    }
  }
}
