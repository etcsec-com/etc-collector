/**
 * Azure OAuth 2.0 Authentication Provider
 * Handles client credentials flow
 * TODO: Full implementation in Story 1.6
 */
export class AzureAuthProvider {
  async getAccessToken(): Promise<string> {
    throw new Error('Azure auth token not implemented yet');
  }

  async refreshToken(): Promise<string> {
    throw new Error('Azure token refresh not implemented yet');
  }
}
