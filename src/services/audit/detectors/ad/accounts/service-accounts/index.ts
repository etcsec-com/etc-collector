/**
 * Service Account Detectors
 * Re-exports all service account vulnerability detectors
 */

export { detectServiceAccountWithSpn } from './with-spn';
export { detectServiceAccountNaming } from './naming';
export { detectServiceAccountOldPassword } from './old-password';
export { detectServiceAccountPrivileged } from './privileged';
export { detectServiceAccountNoPreauth } from './no-preauth';
export { detectServiceAccountWeakEncryption } from './weak-encryption';
export { detectServiceAccountInteractive } from './interactive';

// Export utilities for other modules that may need them
export { SERVICE_ACCOUNT_PATTERNS, getServicePrincipalNames, isServiceAccount } from './utils';
