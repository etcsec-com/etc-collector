/**
 * Microsoft Graph User Queries
 * TODO: Full implementation in Story 1.6
 */
export const GraphUserQueries = {
  ALL_USERS: '/users',
  ENABLED_USERS: '/users?$filter=accountEnabled eq true',
  DISABLED_USERS: '/users?$filter=accountEnabled eq false',
  ADMIN_USERS: '/directoryRoles/members',
};
