import { Client } from 'ldapts';

/**
 * Simple LDAP Connectivity Test
 *
 * Requires environment variables:
 * TEST_LDAP_URL, TEST_LDAP_BIND_DN, TEST_LDAP_BIND_PASSWORD
 *
 * SKIPPED by default if not set.
 */

const TEST_CONFIG = process.env['TEST_LDAP_URL']
  ? {
      url: process.env['TEST_LDAP_URL'],
      bindDN: process.env['TEST_LDAP_BIND_DN'] || '',
      bindPassword: process.env['TEST_LDAP_BIND_PASSWORD'] || '',
      timeout: 5000,
      connectTimeout: 5000,
      tlsOptions: {
        rejectUnauthorized: process.env['TEST_LDAP_TLS_VERIFY'] === 'true',
      },
    }
  : null;

const describeTest = TEST_CONFIG ? describe : describe.skip;

describeTest('LDAP Connectivity Test', () => {
  it('should connect to LDAPS server', async () => {
    if (!TEST_CONFIG) {
      throw new Error('TEST_LDAP_CONFIG not set');
    }

    const client = new Client(TEST_CONFIG);

    try {
      await client.bind(TEST_CONFIG.bindDN, TEST_CONFIG.bindPassword);
      await client.unbind();
      expect(true).toBe(true);
    } catch (error) {
      console.error('Connection error:', error);
      throw error;
    }
  }, 10000);
});
