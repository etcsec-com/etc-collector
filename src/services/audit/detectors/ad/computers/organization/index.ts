/**
 * Organization Detectors
 * Re-exports all organization-related computer vulnerability detectors
 */

export { detectComputerWrongOu } from './wrong-ou';
export { detectDcNotInDcOu } from './dc-not-in-dc-ou';
export { detectWorkstationInServerOu } from './workstation-in-server-ou';
export { detectServerNoAdminGroup } from './server-no-admin-group';
