/**
 * Permissions Detector Utilities
 */

import { AclEntry } from '../../../../../types/ad.types';

/**
 * Helper to get unique objects from ACL entries
 */
export function getUniqueObjects(entries: AclEntry[]): string[] {
  return [...new Set(entries.map((ace) => ace.objectDn))];
}
