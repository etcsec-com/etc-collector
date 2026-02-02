/**
 * Status Detector Utilities
 * Helper functions for status-related detectors
 */

/**
 * Convert Windows FILETIME to JavaScript Date
 * FILETIME: 100-nanosecond intervals since January 1, 1601
 */
export function filetimeToDate(filetime: string | number | undefined): Date | null {
  if (!filetime) return null;
  const ft = typeof filetime === 'string' ? BigInt(filetime) : BigInt(filetime);
  // 0 or max value (never expires) should return null
  if (ft === BigInt(0) || ft === BigInt('9223372036854775807')) return null;
  // Convert to milliseconds since Unix epoch
  // FILETIME epoch is 1601-01-01, Unix epoch is 1970-01-01
  // Difference: 11644473600000 milliseconds
  const ms = Number(ft / BigInt(10000)) - 11644473600000;
  return new Date(ms);
}
