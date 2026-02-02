/**
 * Privileged Accounts Detectors
 * Re-exports all privileged account vulnerability detectors
 */

export { detectSensitiveDelegation } from './sensitive-delegation';
export { detectDisabledAccountInAdminGroup } from './disabled-admin-group';
export { detectExpiredAccountInAdminGroup } from './expired-admin-group';
export { detectSidHistory } from './sid-history';
export { detectNotInProtectedUsers } from './not-in-protected-users';
export { detectDomainAdminInDescription } from './domain-admin-description';
export { detectBackupOperatorsMember } from './backup-operators';
export { detectAccountOperatorsMember } from './account-operators';
export { detectServerOperatorsMember } from './server-operators';
export { detectPrintOperatorsMember } from './print-operators';
