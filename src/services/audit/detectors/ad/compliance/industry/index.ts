/**
 * Industry Framework Compliance Detectors
 * Re-exports all industry framework (PCI-DSS, SOC2, GDPR, SOX, DORA, HIPAA, ISO27001) compliance detectors
 */

export { detectMfaNotEnforced } from './mfa-not-enforced';
export { detectBackupNotVerified } from './backup-not-verified';
export { detectAuditLogRetentionShort } from './audit-log-retention';
export { detectPrivilegedAccessReviewMissing } from './privileged-access-review';
export { detectDataClassificationMissing } from './data-classification';
export { detectChangeManagementBypass } from './change-management-bypass';
export { detectVendorAccountUnmonitored } from './vendor-account-unmonitored';
export { detectEncryptionAtRestDisabled } from './encryption-at-rest';
