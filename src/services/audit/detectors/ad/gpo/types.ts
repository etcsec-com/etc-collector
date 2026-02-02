/**
 * GPO Detector Shared Types and Constants
 *
 * Shared constants and helper functions for GPO vulnerability detection.
 */

import {
  ADGPO,
  LAPS_CSE_GUID,
  LAPS_LEGACY_CSE_GUID,
} from '../../../../../types/gpo.types';

// Well-known SIDs for security filtering analysis
export const SID_AUTHENTICATED_USERS = 'S-1-5-11';
export const SID_EVERYONE = 'S-1-1-0';
export const SID_DOMAIN_COMPUTERS = '-515'; // Ends with this RID

// "Apply Group Policy" extended right GUID
export const APPLY_GROUP_POLICY_RIGHT = 0x00000004; // Read + Execute equivalent for GPO

/**
 * Check if GPO has LAPS Client-Side Extension
 */
export function hasLapsCse(gpo: ADGPO): boolean {
  const extensions = gpo.gPCMachineExtensionNames || '';
  return extensions.includes(LAPS_CSE_GUID) || extensions.includes(LAPS_LEGACY_CSE_GUID);
}
