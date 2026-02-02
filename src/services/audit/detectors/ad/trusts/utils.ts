/**
 * Trust Detector Utilities
 * Shared constants for trust encryption types
 */

// Encryption type bit flags from msDS-SupportedEncryptionTypes
export const ENC_TYPE_DES_CBC_CRC = 0x1;
export const ENC_TYPE_DES_CBC_MD5 = 0x2;
export const ENC_TYPE_RC4_HMAC = 0x4;
export const ENC_TYPE_AES128 = 0x8;
export const ENC_TYPE_AES256 = 0x10;
export const ENC_WEAK_ONLY = ENC_TYPE_DES_CBC_CRC | ENC_TYPE_DES_CBC_MD5 | ENC_TYPE_RC4_HMAC;
export const ENC_AES_TYPES = ENC_TYPE_AES128 | ENC_TYPE_AES256;
