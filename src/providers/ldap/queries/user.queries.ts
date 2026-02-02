/**
 * Predefined LDAP User Queries
 * TODO: Full implementation in Story 1.5
 */
export const UserQueries = {
  ALL_USERS: '(objectClass=user)',
  ENABLED_USERS: '(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
  DISABLED_USERS: '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))',
  ADMIN_USERS: '(&(objectClass=user)(adminCount=1))',
};
