/**
 * Other Advanced Detectors
 * Re-exports miscellaneous advanced vulnerability detectors
 */

export { detectDelegationPrivilege } from './delegation-privilege';
export { detectForeignSecurityPrincipals } from './foreign-security-principals';
export { detectNtlmRelayOpportunity } from './ntlm-relay-opportunity';
export { detectDangerousLogonScripts } from './dangerous-logon-scripts';
export { detectDsHeuristicsModified } from './ds-heuristics-modified';
export { detectAdminSdHolderModified } from './admin-sd-holder-modified';
export { detectExchangePrivEscPath } from './exchange-priv-esc-path';
