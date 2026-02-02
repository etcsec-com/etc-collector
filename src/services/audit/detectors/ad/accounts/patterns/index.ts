/**
 * Pattern Detectors
 * Re-exports all dangerous pattern vulnerability detectors
 */

export { detectTestAccount } from './test-account';
export { detectSharedAccount } from './shared-account';
export { detectSmartcardNotRequired } from './smartcard-not-required';
export { detectPrimaryGroupIdSpoofing } from './primarygroupid-spoofing';
