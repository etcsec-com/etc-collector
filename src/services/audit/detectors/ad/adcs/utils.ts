/**
 * ADCS Detector Utilities
 *
 * Shared helper functions for ESC vulnerability detection.
 */

import {
  EKU_CLIENT_AUTH,
  EKU_PKIINIT_CLIENT_AUTH,
  EKU_SMART_CARD_LOGON,
} from '../../../../../types/adcs.types';

/**
 * Check if template allows authentication (client auth, smartcard, PKINIT)
 */
export function hasAuthenticationEku(ekus: string[]): boolean {
  return (
    ekus.includes(EKU_CLIENT_AUTH) ||
    ekus.includes(EKU_PKIINIT_CLIENT_AUTH) ||
    ekus.includes(EKU_SMART_CARD_LOGON) ||
    ekus.length === 0 // No EKU = any purpose
  );
}
