/**
 * Computer Detector Utilities
 * Helper functions for computer-related detectors
 */

/**
 * Windows FILETIME epoch offset in milliseconds
 * Difference between 1601-01-01 and 1970-01-01
 */
export const FILETIME_EPOCH_OFFSET = 11644473600000;

/**
 * Convert Windows FILETIME to Unix timestamp in milliseconds
 */
export function filetimeToTimestamp(filetime: number): number | null {
  // Invalid or "Never" values
  if (filetime === 0 || filetime >= Number.MAX_SAFE_INTEGER) {
    return null;
  }

  // Convert 100-ns intervals to milliseconds and adjust epoch
  const ms = filetime / 10000 - FILETIME_EPOCH_OFFSET;

  // Validate reasonable range (year 1970 to 2100)
  if (ms < 0 || ms > 4102444800000) {
    return null;
  }

  return ms;
}

/**
 * Convert any date format to timestamp in milliseconds
 * Handles: Date object, ISO string, FILETIME (number/string), undefined/null
 *
 * @param value - Date in any format
 * @returns Timestamp in milliseconds, or null if invalid
 */
export function toTimestamp(value: any): number | null {
  if (!value) return null;

  // Already a Date object
  if (value instanceof Date) {
    const time = value.getTime();
    return isNaN(time) ? null : time;
  }

  // String value
  if (typeof value === 'string') {
    // Try ISO date first (e.g., "2024-01-15T10:30:00.000Z")
    if (value.includes('-') && value.includes('T')) {
      const date = new Date(value);
      const time = date.getTime();
      return isNaN(time) ? null : time;
    }

    // Try LDAP generalizedTime format (e.g., "20260115123456.0Z" or "20260115123456Z")
    const gtMatch = value.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/);
    if (gtMatch && gtMatch[1] && gtMatch[2] && gtMatch[3] && gtMatch[4] && gtMatch[5] && gtMatch[6]) {
      const date = new Date(
        Date.UTC(
          parseInt(gtMatch[1], 10),
          parseInt(gtMatch[2], 10) - 1,
          parseInt(gtMatch[3], 10),
          parseInt(gtMatch[4], 10),
          parseInt(gtMatch[5], 10),
          parseInt(gtMatch[6], 10)
        )
      );
      const time = date.getTime();
      return isNaN(time) ? null : time;
    }

    // Try as numeric FILETIME string
    const parsed = parseInt(value, 10);
    if (!isNaN(parsed) && parsed > 0) {
      return filetimeToTimestamp(parsed);
    }
    return null;
  }

  // Number - could be FILETIME or Unix timestamp
  if (typeof value === 'number') {
    if (value <= 0) return null;
    // FILETIME values are huge (> 100 trillion), Unix timestamps are ~1.7 trillion ms
    if (value > 100000000000000) {
      return filetimeToTimestamp(value);
    }
    // If it's reasonable (after year 2000 and before year 2100)
    if (value > 946684800000 && value < 4102444800000) {
      return value; // Already a Unix timestamp in ms
    }
    // Could be Unix seconds
    if (value > 946684800 && value < 4102444800) {
      return value * 1000;
    }
    // Assume FILETIME
    return filetimeToTimestamp(value);
  }

  return null;
}
