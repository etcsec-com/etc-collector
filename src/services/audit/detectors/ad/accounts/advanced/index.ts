/**
 * Advanced Detectors
 * Re-exports all Phase 2C and Phase 4 vulnerability detectors
 */

// Phase 2C Enhanced Detections
export { detectAdminCountOrphaned } from './admin-count-orphaned';
export { detectPrivilegedAccountSpn } from './privileged-account-spn';
export { detectAdminNoSmartcard } from './admin-no-smartcard';

// Phase 4 Advanced Detections
export { detectReplicaDirectoryChanges } from './replica-directory-changes';
export { detectDangerousBuiltinMembership } from './dangerous-builtin-membership';
export { detectLockedAccountAdmin } from './locked-account-admin';
