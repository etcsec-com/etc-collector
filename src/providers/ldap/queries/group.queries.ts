/**
 * Predefined LDAP Group Queries
 * TODO: Full implementation in Story 1.5
 */
export const GroupQueries = {
  ALL_GROUPS: '(objectClass=group)',
  SECURITY_GROUPS: '(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=2147483648))',
  DISTRIBUTION_GROUPS: '(&(objectClass=group)(!(groupType:1.2.840.113556.1.4.803:=2147483648)))',
};
