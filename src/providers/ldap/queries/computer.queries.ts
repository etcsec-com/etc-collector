/**
 * Predefined LDAP Computer Queries
 * TODO: Full implementation in Story 1.5
 */
export const ComputerQueries = {
  ALL_COMPUTERS: '(objectClass=computer)',
  SERVERS: '(&(objectClass=computer)(operatingSystem=*Server*))',
  WORKSTATIONS: '(&(objectClass=computer)(!(operatingSystem=*Server*)))',
};
