/**
 * Enrollment Service
 * Handles collector enrollment with SaaS platform
 */

import * as os from 'os';
import { logInfo } from '../../utils/logger';
import { SaaSClientService } from './saas-client.service';
import { CredentialStoreService } from './credential-store.service';
import { EnrollmentRequest, CollectorCredentials } from '../../types/saas.types';
import { version } from '../../../package.json';

export class EnrollmentService {
  private readonly credentialStore: CredentialStoreService;

  constructor(credentialStore?: CredentialStoreService) {
    this.credentialStore = credentialStore || new CredentialStoreService();
  }

  /**
   * Enroll the collector with SaaS platform
   */
  async enroll(enrollmentToken: string, saasUrl: string): Promise<void> {
    logInfo('Starting enrollment process');

    // Check if already enrolled
    if (this.credentialStore.exists()) {
      const credentials = await this.credentialStore.load();
      if (credentials) {
        throw new Error(
          `Collector already enrolled as ${credentials.collectorId}. ` +
            `Run with --unenroll first to re-enroll.`
        );
      }
    }

    // Create SaaS client
    const saasClient = new SaaSClientService(saasUrl);

    // Build enrollment request
    const request: EnrollmentRequest = {
      enrollmentToken,
      hostname: os.hostname(),
      osType: process.platform,
      osVersion: `${os.type()} ${os.release()}`,
      collectorVersion: version,
      capabilities: ['ad-audit', 'azure-audit'],
    };

    // Enroll with SaaS
    const response = await saasClient.enroll(request);

    if (!response.success) {
      throw new Error(
        response.message || 'Enrollment failed without error message'
      );
    }

    // Save credentials locally
    const credentials: CollectorCredentials = {
      collectorId: response.collectorId,
      apiKey: response.apiKey,
      saasUrl,
      enrolledAt: new Date().toISOString(),
      config: response.config,
    };

    await this.credentialStore.save(credentials);

    console.log('\n✅ Enrollment successful!\n');
    console.log(`Collector ID: ${response.collectorId}`);
    console.log(`SaaS URL: ${saasUrl}`);
    console.log(`\nConfiguration received:`);
    if (response.config.ldap) {
      console.log(`  LDAP URL: ${response.config.ldap.url}`);
      console.log(`  Base DN: ${response.config.ldap.baseDN}`);
    }
    if (response.config.azure?.enabled) {
      console.log(`  Azure: Enabled`);
      console.log(`  Tenant: ${response.config.azure.tenantId}`);
    }
    console.log(`  Polling interval: ${response.config.polling.intervalSeconds}s`);
    console.log('\n📡 To start the agent, run:');
    console.log(`   etc-collector --daemon\n`);
  }

  /**
   * Unenroll the collector
   */
  async unenroll(): Promise<void> {
    logInfo('Starting unenrollment process');

    if (!this.credentialStore.exists()) {
      console.log('⚠️  Collector is not enrolled');
      return;
    }

    const credentials = await this.credentialStore.load();
    if (credentials) {
      console.log(`\nUnenrolling collector: ${credentials.collectorId}`);
    }

    this.credentialStore.delete();

    console.log('✅ Collector unenrolled successfully\n');
  }

  /**
   * Show enrollment status
   */
  async showStatus(): Promise<void> {
    if (!this.credentialStore.exists()) {
      console.log('\n❌ Collector is not enrolled');
      console.log('\nTo enroll, run:');
      console.log('   etc-collector --enroll --token=<your-token>\n');
      return;
    }

    const credentials = await this.credentialStore.load();

    if (!credentials) {
      console.log('\n⚠️  Enrollment file exists but could not be loaded');
      console.log('   This might happen if the file is corrupted or was created on a different machine');
      console.log(`\nCredentials file: ${this.credentialStore.getPath()}`);
      console.log('\nTo re-enroll:');
      console.log('   1. etc-collector --unenroll');
      console.log('   2. etc-collector --enroll --token=<your-token>\n');
      return;
    }

    console.log('\n✅ Collector is enrolled\n');
    console.log(`Collector ID: ${credentials.collectorId}`);
    console.log(`SaaS URL: ${credentials.saasUrl}`);
    console.log(`Enrolled at: ${credentials.enrolledAt}`);
    console.log(`\nConfiguration:`);

    if (credentials.config.ldap) {
      console.log(`  LDAP:`);
      console.log(`    URL: ${credentials.config.ldap.url}`);
      console.log(`    Base DN: ${credentials.config.ldap.baseDN}`);
      console.log(`    Bind DN: ${credentials.config.ldap.bindDN}`);
    }

    if (credentials.config.azure?.enabled) {
      console.log(`  Azure:`);
      console.log(`    Enabled: Yes`);
      console.log(`    Tenant ID: ${credentials.config.azure.tenantId || 'N/A'}`);
      console.log(`    Tenant Name: ${credentials.config.azure.tenantName || 'N/A'}`);
    }

    console.log(`  Polling:`);
    console.log(`    Interval: ${credentials.config.polling.intervalSeconds}s`);
    console.log(`    Timeout: ${credentials.config.polling.commandTimeoutSeconds}s`);

    console.log(`\nCredentials file: ${this.credentialStore.getPath()}`);
    console.log('\n📡 To start the agent, run:');
    console.log('   etc-collector --daemon\n');
  }

  /**
   * Load stored credentials
   */
  async loadCredentials(): Promise<CollectorCredentials | null> {
    return await this.credentialStore.load();
  }
}
