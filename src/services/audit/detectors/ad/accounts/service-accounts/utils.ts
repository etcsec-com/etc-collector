/**
 * Service Account Utilities
 * Helper functions and patterns for service account detectors
 */

import { ADUser } from '../../../../../../types/ad.types';

/**
 * Service account naming patterns for detection
 */
export const SERVICE_ACCOUNT_PATTERNS = [
  /^svc[_-]/i, // svc_xxx, svc-xxx
  /[_-]svc$/i, // xxx_svc, xxx-svc
  /^service[_-]/i, // service_xxx, service-xxx
  /[_-]service$/i, // xxx_service
  /^sa[_-]/i, // sa_xxx (service account prefix)
  /[_-]sa$/i, // xxx_sa
  /^app[_-]/i, // app_xxx (application account)
  /^sql[_-]/i, // sql_xxx (SQL service)
  /^iis[_-]/i, // iis_xxx (IIS service)
  /^web[_-]/i, // web_xxx
  /^batch[_-]/i, // batch_xxx
  /^task[_-]/i, // task_xxx
  /^job[_-]/i, // job_xxx
  /^daemon[_-]/i, // daemon_xxx
  /^agent[_-]/i, // agent_xxx
];

/**
 * Get service principal names from user (handles index signature)
 */
export function getServicePrincipalNames(user: ADUser): string[] {
  const spn = (user as any)['servicePrincipalName'];
  if (!spn) return [];
  if (Array.isArray(spn)) return spn;
  return [spn as string];
}

/**
 * Check if user is a service account (has SPN or matches naming pattern)
 */
export function isServiceAccount(user: ADUser): boolean {
  // Has SPN = definitely a service account
  const spns = getServicePrincipalNames(user);
  if (spns.length > 0) {
    return true;
  }
  // Matches service naming pattern
  return SERVICE_ACCOUNT_PATTERNS.some((pattern) => pattern.test(user.sAMAccountName));
}
