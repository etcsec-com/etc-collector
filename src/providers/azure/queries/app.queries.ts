/**
 * Microsoft Graph Application Queries
 * TODO: Full implementation in Story 1.6
 */
export const GraphAppQueries = {
  ALL_APPS: '/applications',
  SERVICE_PRINCIPALS: '/servicePrincipals',
  APP_REGISTRATIONS: '/applications?$filter=signInAudience eq \'AzureADMyOrg\'',
};
