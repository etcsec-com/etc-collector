/**
 * Dangerous Permission Detectors (High/Critical severity)
 * Re-exports all high/critical severity permission detectors
 */

export { detectAclGenericAll } from './genericall';
export { detectAclWriteDacl } from './writedacl';
export { detectAclWriteOwner } from './writeowner';
export { detectAclSelfMembership } from './self-membership';
export { detectAclDsReplicationGetChanges } from './dcsync';
