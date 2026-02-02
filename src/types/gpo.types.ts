/**
 * GPO (Group Policy Object) Types
 *
 * Types for GPO security analysis.
 */

/**
 * Group Policy Object
 */
export interface ADGPO {
  dn: string;
  cn: string; // GUID
  displayName?: string;
  gPCFileSysPath?: string;

  // Flags: 0=enabled, 1=user disabled, 2=computer disabled, 3=all disabled
  flags?: number;

  // Version info
  versionNumber?: number;

  // Security descriptor for ACL analysis
  nTSecurityDescriptor?: Buffer;

  // Machine/User extension GUIDs (for detecting LAPS, etc.)
  gPCMachineExtensionNames?: string;
  gPCUserExtensionNames?: string;

}

/**
 * GPO Link information
 */
export interface GPOLink {
  gpoGuid: string;
  gpoDn?: string;
  linkedTo: string; // OU/Domain DN
  linkOrder?: number;
  enforced: boolean;
  disabled: boolean;
}

/**
 * GPO ACL Entry for permission analysis
 */
export interface GPOAclEntry {
  gpoDn: string;
  gpoName: string;
  trustee: string;
  trusteeSid: string;
  accessMask: number;
  aceType: number;
}

// GPO Flags
export const GPO_FLAG_USER_DISABLED = 0x00000001;
export const GPO_FLAG_COMPUTER_DISABLED = 0x00000002;
export const GPO_FLAG_ALL_DISABLED = 0x00000003;

// GPO Link Flags (from gPOptions)
export const GPO_LINK_DISABLED = 0x00000001;
export const GPO_LINK_ENFORCED = 0x00000002;

// LAPS Client-Side Extension GUID
export const LAPS_CSE_GUID = '{D76B9641-3288-4f75-942D-087DE603E3EA}';
export const LAPS_LEGACY_CSE_GUID = '{169EBF44-942F-4C43-87CE-13C93996EBBE}';

// Common GPO rights
export const GPO_RIGHT_WRITE = 0x00000002;
export const GPO_RIGHT_WRITE_DAC = 0x00040000;
export const GPO_RIGHT_WRITE_OWNER = 0x00080000;
export const GPO_RIGHT_GENERIC_WRITE = 0x40000000;
