/**
 * Compliance Detector Types
 * Type definitions for compliance vulnerability detectors
 */

/**
 * Password policy interface (from ADDomain)
 */
export interface PasswordPolicy {
  minPwdLength: number;
  pwdHistoryLength: number;
  lockoutThreshold: number;
  lockoutDuration: number;
  maxPwdAge: number;
  minPwdAge: number;
  complexityEnabled: boolean;
  reversibleEncryption: boolean;
}

/**
 * Framework tracking interface
 */
export interface FrameworkScore {
  total: number;
  passed: number;
}
