/**
 * Advanced Detector Types
 * Type definitions for advanced vulnerability detectors
 */

/**
 * GPO Security Settings from SYSVOL
 */
export interface GpoSecuritySettings {
  /** LDAP server signing requirement: 0=none, 1=negotiate, 2=require */
  ldapServerIntegrity?: number;
  /** LDAP channel binding: 0=never, 1=when supported, 2=always */
  ldapChannelBinding?: number;
  /** SMBv1 server enabled */
  smbv1ServerEnabled?: boolean;
  /** SMBv1 client enabled */
  smbv1ClientEnabled?: boolean;
  /** SMB Server signing required (RequireSecuritySignature) */
  smbSigningRequired?: boolean;
  /** SMB Client signing required */
  smbClientSigningRequired?: boolean;
  /** Audit policies configured */
  auditPolicies?: {
    category: string;
    subcategory?: string;
    success: boolean;
    failure: boolean;
  }[];
  /** PowerShell logging settings */
  powershellLogging?: {
    moduleLogging: boolean;
    scriptBlockLogging: boolean;
    transcription: boolean;
  };
}

/**
 * Advanced detector options
 */
export interface AdvancedDetectorOptions {
  /** GPO security settings from SYSVOL */
  gpoSettings?: GpoSecuritySettings | null;
  /** Whether anonymous LDAP access is allowed */
  anonymousAccessAllowed?: boolean;
}
