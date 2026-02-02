/**
 * SMB Provider
 *
 * Provides SMB2/3 access to Windows shares (SYSVOL, etc.)
 * Used to read Group Policy files like GptTmpl.inf for Kerberos policy.
 *
 * Uses smbclient CLI tool for better compatibility with Windows servers.
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import { readFile as fsReadFile, unlink } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { logger } from '../../utils/logger';

const execAsync = promisify(exec);

/**
 * SMB connection configuration
 */
export interface SMBConfig {
  /** Domain controller hostname or IP */
  host: string;
  /** SMB share name (e.g., 'SYSVOL') */
  share: string;
  /** Domain name */
  domain: string;
  /** Username for authentication */
  username: string;
  /** Password for authentication */
  password: string;
  /** Connection timeout in ms (default: 10000) */
  timeout?: number;
}

/**
 * Kerberos policy from GptTmpl.inf
 */
export interface KerberosPolicy {
  maxTicketAge: number; // hours
  maxRenewAge: number; // days
  maxServiceAge: number; // minutes
  maxClockSkew: number; // minutes
  ticketValidateClient: boolean;
}

/**
 * Security settings extracted from GPO files
 */
export interface GpoSecuritySettings {
  /** LDAP server signing requirement: 0=none, 1=negotiate, 2=require */
  ldapServerIntegrity?: number;
  /** LDAP channel binding: 0=never, 1=when supported, 2=always */
  ldapChannelBinding?: number;
  /** SMBv1 server enabled */
  smbv1ServerEnabled?: boolean;
  /** SMBv1 client enabled */
  smbv1ClientEnabled?: boolean;
  /** SMB Server signing required (RequireSecuritySignature) */
  smbSigningRequired?: boolean;
  /** SMB Client signing required */
  smbClientSigningRequired?: boolean;
  /** Audit policies configured */
  auditPolicies?: {
    category: string;
    subcategory?: string;
    success: boolean;
    failure: boolean;
  }[];
  /** PowerShell logging settings */
  powershellLogging?: {
    moduleLogging: boolean;
    scriptBlockLogging: boolean;
    transcription: boolean;
  };
}

/**
 * Default Domain Policy GUID (well-known)
 */
const DEFAULT_DOMAIN_POLICY_GUID = '{31B2F340-016D-11D2-945F-00C04FB984F9}';

/**
 * SMB Provider for reading Windows shares using smbclient
 */
export class SMBProvider {
  private config: SMBConfig;

  constructor(config: SMBConfig) {
    this.config = {
      timeout: 15000,
      ...config,
    };
  }

  /**
   * Connect to SMB share (no-op for smbclient - stateless)
   */
  async connect(): Promise<void> {
    logger.debug('SMB provider ready (using smbclient)', { host: this.config.host, share: this.config.share });
  }

  /**
   * Disconnect from SMB share (no-op for smbclient - stateless)
   */
  async disconnect(): Promise<void> {
    // No-op for smbclient
  }

  /**
   * Build smbclient command base (without the -c command part)
   */
  private buildSmbCommand(): string {
    const { host, share, domain, username, password } = this.config;
    // smbclient //server/share -U domain\user%password -c "command"
    // Escape special characters in password
    const escapedPassword = password.replace(/'/g, "'\\''");
    return `smbclient '//${host}/${share}' -U '${domain}\\${username}%${escapedPassword}' -c`;
  }

  /**
   * Read a file from the SMB share using smbclient
   */
  async readFile(path: string): Promise<string> {
    const timeout = this.config.timeout || 15000;
    const tempFile = join(tmpdir(), `smb_${Date.now()}_${Math.random().toString(36).substring(7)}`);

    // Convert Windows path to SMB path format
    const smbPath = path.replace(/\\/g, '/');

    const cmd = `${this.buildSmbCommand()} 'get "${smbPath}" "${tempFile}"'`;

    try {
      logger.debug('SMB readFile', { path: smbPath, tempFile });

      await execAsync(cmd, { timeout });

      const content = await fsReadFile(tempFile, 'utf8');

      // Cleanup temp file
      try {
        await unlink(tempFile);
      } catch {
        // Ignore cleanup errors
      }

      return content;
    } catch (error) {
      // Cleanup temp file on error
      try {
        await unlink(tempFile);
      } catch {
        // Ignore cleanup errors
      }

      const message = error instanceof Error ? error.message : 'Unknown error';
      logger.debug('SMB readFile failed', { path: smbPath, error: message });
      throw new Error(`SMB readFile failed: ${message}`);
    }
  }

  /**
   * Read a binary file from the SMB share
   */
  async readBinaryFile(path: string): Promise<Buffer> {
    const timeout = this.config.timeout || 15000;
    const tempFile = join(tmpdir(), `smb_${Date.now()}_${Math.random().toString(36).substring(7)}`);

    // Convert Windows path to SMB path format
    const smbPath = path.replace(/\\/g, '/');

    const cmd = `${this.buildSmbCommand()} 'get "${smbPath}" "${tempFile}"'`;

    try {
      await execAsync(cmd, { timeout });
      const content = await fsReadFile(tempFile);

      // Cleanup temp file
      try {
        await unlink(tempFile);
      } catch {
        // Ignore cleanup errors
      }

      return content;
    } catch (error) {
      // Cleanup temp file on error
      try {
        await unlink(tempFile);
      } catch {
        // Ignore cleanup errors
      }

      throw error;
    }
  }

  /**
   * Check if a file exists on the SMB share
   */
  async exists(path: string): Promise<boolean> {
    const timeout = this.config.timeout || 15000;

    // Convert Windows path to SMB path format
    const smbPath = path.replace(/\\/g, '/');

    // Use 'ls' command to check if file exists
    // Extract directory and filename
    const lastSlash = smbPath.lastIndexOf('/');
    const dir = lastSlash > 0 ? smbPath.substring(0, lastSlash) : '';
    const filename = lastSlash > 0 ? smbPath.substring(lastSlash + 1) : smbPath;

    const cmd = `${this.buildSmbCommand()} 'cd "${dir}"; ls "${filename}"'`;

    try {
      logger.debug('SMB exists check', { path: smbPath, dir, filename });

      const { stdout } = await execAsync(cmd, { timeout });

      // If we get output and it contains the filename, the file exists
      const exists = stdout.includes(filename);
      logger.debug('SMB exists result', { path: smbPath, exists });

      return exists;
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      logger.debug('SMB exists check failed (file likely does not exist)', { path: smbPath, error: message });
      return false;
    }
  }

  /**
   * Read Kerberos policy from Default Domain Policy GPO
   */
  async readKerberosPolicy(domainDnsName: string): Promise<KerberosPolicy | null> {
    const gptTmplPath = `${domainDnsName}/Policies/${DEFAULT_DOMAIN_POLICY_GUID}/Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf`;

    try {
      logger.debug('Reading GptTmpl.inf for Kerberos policy', { path: gptTmplPath });

      const exists = await this.exists(gptTmplPath);
      if (!exists) {
        logger.warn('GptTmpl.inf not found', { path: gptTmplPath });
        return null;
      }

      const content = await this.readFile(gptTmplPath);
      return this.parseKerberosPolicy(content);
    } catch (error) {
      logger.warn('Failed to read Kerberos policy from SYSVOL', { error, path: gptTmplPath });
      return null;
    }
  }

  /**
   * Parse Kerberos policy from GptTmpl.inf content
   */
  private parseKerberosPolicy(content: string): KerberosPolicy {
    const policy: KerberosPolicy = {
      maxTicketAge: 10, // Default: 10 hours
      maxRenewAge: 7, // Default: 7 days
      maxServiceAge: 600, // Default: 600 minutes
      maxClockSkew: 5, // Default: 5 minutes
      ticketValidateClient: true,
    };

    // Find [Kerberos Policy] section
    const lines = content.split(/\r?\n/);
    let inKerberosSection = false;

    for (const line of lines) {
      const trimmedLine = line.trim();

      // Check for section headers
      if (trimmedLine.startsWith('[')) {
        inKerberosSection = trimmedLine.toLowerCase() === '[kerberos policy]';
        continue;
      }

      if (!inKerberosSection) continue;

      // Parse key=value pairs
      const match = trimmedLine.match(/^(\w+)\s*=\s*(.+)$/);
      if (!match || !match[1] || !match[2]) continue;

      const key = match[1];
      const value = match[2];
      const numValue = parseInt(value, 10);

      switch (key.toLowerCase()) {
        case 'maxticketage':
          policy.maxTicketAge = numValue;
          break;
        case 'maxrenewage':
          policy.maxRenewAge = numValue;
          break;
        case 'maxserviceage':
          policy.maxServiceAge = numValue;
          break;
        case 'maxclockskew':
          policy.maxClockSkew = numValue;
          break;
        case 'ticketvalidateclient':
          policy.ticketValidateClient = numValue === 1;
          break;
      }
    }

    return policy;
  }

  /**
   * Read GPO security settings from Default Domain Controllers Policy
   * Reads GptTmpl.inf [Registry Values] section for LDAP signing, SMBv1, etc.
   */
  async readGpoSecuritySettings(domainDnsName: string): Promise<GpoSecuritySettings | null> {
    // Default Domain Controllers Policy GUID
    const DC_POLICY_GUID = '{6AC1786C-016F-11D2-945F-00C04FB984F9}';
    const gptTmplPath = `${domainDnsName}/Policies/${DC_POLICY_GUID}/Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf`;

    const settings: GpoSecuritySettings = {};

    try {
      // Read GptTmpl.inf for registry values from DC Policy
      logger.debug('Reading GPO security settings', { path: gptTmplPath });

      const dcPolicyExists = await this.exists(gptTmplPath);
      if (dcPolicyExists) {
        const content = await this.readFile(gptTmplPath);
        this.parseRegistryValues(content, settings);
        logger.debug('Parsed DC Policy GptTmpl.inf', { settings });
      }

      // Also check Default Domain Policy for additional settings
      const domainPolicyPath = `${domainDnsName}/Policies/${DEFAULT_DOMAIN_POLICY_GUID}/Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf`;
      const domainPolicyExists = await this.exists(domainPolicyPath);
      if (domainPolicyExists) {
        const domainContent = await this.readFile(domainPolicyPath);
        this.parseRegistryValues(domainContent, settings);
        logger.debug('Parsed Domain Policy GptTmpl.inf', { settings });
      }

      // Try to read audit.csv for audit policy
      await this.readAuditPolicy(domainDnsName, DC_POLICY_GUID, settings);

      // Try to read registry.pol for PowerShell logging
      await this.readPowerShellLogging(domainDnsName, DC_POLICY_GUID, settings);

      logger.info('Successfully fetched GPO security settings', {
        hasLdapSigning: settings.ldapServerIntegrity !== undefined,
        hasSmbSigning: settings.smbSigningRequired !== undefined,
        hasAuditPolicy: settings.auditPolicies !== undefined,
        hasPsLogging: settings.powershellLogging !== undefined,
      });

      return settings;
    } catch (error) {
      logger.warn('Failed to read GPO security settings', { error });
      return null;
    }
  }

  /**
   * Parse [Registry Values] section from GptTmpl.inf
   */
  private parseRegistryValues(content: string, settings: GpoSecuritySettings): void {
    const lines = content.split(/\r?\n/);
    let inRegistrySection = false;

    for (const line of lines) {
      const trimmedLine = line.trim();

      // Check for section headers
      if (trimmedLine.startsWith('[')) {
        inRegistrySection = trimmedLine.toLowerCase() === '[registry values]';
        continue;
      }

      if (!inRegistrySection) continue;

      // Registry format: MACHINE\path\to\key=type,value
      // Example: MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity=4,2
      const match = trimmedLine.match(/^MACHINE\\(.+?)=(\d+),(.+)$/i);
      if (!match || !match[1] || !match[3]) continue;

      const keyPath = match[1].toLowerCase();
      const value = match[3];

      // LDAP Server Signing
      if (keyPath.includes('ntds\\parameters\\ldapserverintegrity')) {
        settings.ldapServerIntegrity = parseInt(value, 10);
      }

      // LDAP Channel Binding
      if (keyPath.includes('ntds\\parameters\\ldapenforcechannelbinding')) {
        settings.ldapChannelBinding = parseInt(value, 10);
      }

      // SMBv1 Server
      if (keyPath.includes('lanmanserver\\parameters\\smb1')) {
        settings.smbv1ServerEnabled = value === '1';
      }

      // SMBv1 Client (LanmanWorkstation)
      if (keyPath.includes('lanmanworkstation\\parameters\\smb1')) {
        settings.smbv1ClientEnabled = value === '1';
      }

      // Alternative SMBv1 check via MrxSmb10
      if (keyPath.includes('mrxsmb10\\start')) {
        // Start=4 means disabled, anything else means enabled
        settings.smbv1ClientEnabled = value !== '4';
      }

      // SMB Server Signing (RequireSecuritySignature)
      // MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature=4,1
      if (keyPath.includes('lanmanserver\\parameters\\requiresecuritysignature')) {
        settings.smbSigningRequired = value === '1';
      }

      // SMB Client Signing (RequireSecuritySignature)
      // MACHINE\System\CurrentControlSet\Services\LanManWorkstation\Parameters\RequireSecuritySignature=4,1
      if (keyPath.includes('lanmanworkstation\\parameters\\requiresecuritysignature')) {
        settings.smbClientSigningRequired = value === '1';
      }
    }
  }

  /**
   * Read audit policy from audit.csv
   */
  private async readAuditPolicy(
    domainDnsName: string,
    gpoGuid: string,
    settings: GpoSecuritySettings
  ): Promise<void> {
    const auditPath = `${domainDnsName}/Policies/${gpoGuid}/Machine/Microsoft/Windows NT/Audit/audit.csv`;

    try {
      const exists = await this.exists(auditPath);
      if (!exists) return;

      const content = await this.readFile(auditPath);
      settings.auditPolicies = this.parseAuditCsv(content);
    } catch (error) {
      logger.debug('Failed to read audit.csv', { error });
    }
  }

  /**
   * Parse audit.csv content
   * Format: Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value
   */
  private parseAuditCsv(content: string): GpoSecuritySettings['auditPolicies'] {
    const policies: NonNullable<GpoSecuritySettings['auditPolicies']> = [];
    const lines = content.split(/\r?\n/);

    // Skip header line
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i];
      if (!line) continue;

      const trimmedLine = line.trim();
      if (!trimmedLine) continue;

      // CSV parsing (simple - assumes no commas in values)
      const parts = trimmedLine.split(',');
      if (parts.length < 7) continue;

      const subcategory = parts[2];
      const settingValue = parts[6];

      if (!subcategory || !settingValue) continue;

      // Setting values: 0=No Auditing, 1=Success, 2=Failure, 3=Success and Failure
      const value = parseInt(settingValue, 10);

      // Map subcategories to categories
      const category = this.getAuditCategory(subcategory);

      policies.push({
        category,
        subcategory,
        success: (value & 1) !== 0,
        failure: (value & 2) !== 0,
      });
    }

    return policies;
  }

  /**
   * Map audit subcategory to category
   */
  private getAuditCategory(subcategory: string): string {
    const categoryMap: Record<string, string> = {
      'Credential Validation': 'Account Logon',
      'Kerberos Authentication Service': 'Account Logon',
      'Kerberos Service Ticket Operations': 'Account Logon',
      'Computer Account Management': 'Account Management',
      'Security Group Management': 'Account Management',
      'User Account Management': 'Account Management',
      'Logon': 'Logon/Logoff',
      'Logoff': 'Logon/Logoff',
      'Special Logon': 'Logon/Logoff',
      'File System': 'Object Access',
      'Registry': 'Object Access',
      'Kernel Object': 'Object Access',
      'Audit Policy Change': 'Policy Change',
      'Authentication Policy Change': 'Policy Change',
      'Sensitive Privilege Use': 'Privilege Use',
      'Security State Change': 'System',
      'Security System Extension': 'System',
      'System Integrity': 'System',
    };

    for (const [sub, cat] of Object.entries(categoryMap)) {
      if (subcategory.toLowerCase().includes(sub.toLowerCase())) {
        return cat;
      }
    }
    return 'Other';
  }

  /**
   * Read PowerShell logging settings from registry.pol
   * Note: registry.pol is a binary format, this is a simplified implementation
   */
  private async readPowerShellLogging(
    domainDnsName: string,
    gpoGuid: string,
    settings: GpoSecuritySettings
  ): Promise<void> {
    const registryPolPath = `${domainDnsName}/Policies/${gpoGuid}/Machine/Registry.pol`;

    try {
      const exists = await this.exists(registryPolPath);
      if (!exists) return;

      // Registry.pol is a binary format
      // For simplicity, we read as buffer and search for known strings
      const content = await this.readBinaryFile(registryPolPath);
      settings.powershellLogging = this.parsePowerShellLogging(content);
    } catch (error) {
      logger.debug('Failed to read registry.pol', { error });
    }
  }

  /**
   * Parse PowerShell logging settings from registry.pol binary content
   * Registry.pol format: PReg header + entries
   * Each entry: [key;value;type;size;data]
   */
  private parsePowerShellLogging(content: Buffer): GpoSecuritySettings['powershellLogging'] {
    const result = {
      moduleLogging: false,
      scriptBlockLogging: false,
      transcription: false,
    };

    try {
      // Convert to string for simple pattern matching
      // This is a simplified approach - proper parsing would use the binary format
      const textContent = content.toString('utf16le');

      // Look for PowerShell logging registry keys
      // ScriptBlockLogging: Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging
      // ModuleLogging: Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\EnableModuleLogging
      // Transcription: Software\Policies\Microsoft\Windows\PowerShell\Transcription\EnableTranscripting

      if (textContent.includes('EnableScriptBlockLogging') && textContent.includes('\x01\x00\x00\x00')) {
        result.scriptBlockLogging = true;
      }

      if (textContent.includes('EnableModuleLogging') && textContent.includes('\x01\x00\x00\x00')) {
        result.moduleLogging = true;
      }

      if (textContent.includes('EnableTranscripting') && textContent.includes('\x01\x00\x00\x00')) {
        result.transcription = true;
      }
    } catch (error) {
      logger.debug('Failed to parse registry.pol', { error });
    }

    return result;
  }

  /**
   * Test SMB connection using smbclient
   */
  async testConnection(): Promise<{ success: boolean; message: string }> {
    const timeout = this.config.timeout || 15000;

    const cmd = `${this.buildSmbCommand()} 'ls'`;

    try {
      await execAsync(cmd, { timeout });
      return {
        success: true,
        message: 'SMB connection successful',
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      return {
        success: false,
        message: `SMB connection failed: ${message}`,
      };
    }
  }
}

/**
 * Formatted Kerberos policy with isDefault flag
 */
export interface FormattedKerberosPolicy {
  maxTicketAge: string;
  maxRenewAge: string;
  maxServiceAge: string;
  maxClockSkew: string;
  ticketValidateClient: boolean;
  isDefault: boolean;
}

/**
 * Format Kerberos policy values to human-readable strings
 */
export function formatKerberosPolicy(policy: KerberosPolicy, isDefault = false): FormattedKerberosPolicy {
  return {
    maxTicketAge: `${policy.maxTicketAge} hours`,
    maxRenewAge: `${policy.maxRenewAge} days`,
    maxServiceAge: `${policy.maxServiceAge} min`,
    maxClockSkew: `${policy.maxClockSkew} min`,
    ticketValidateClient: policy.ticketValidateClient,
    isDefault,
  };
}

/**
 * Get Windows default Kerberos policy values
 * These are the defaults when no GPO customization is applied
 */
export function getDefaultKerberosPolicy(): FormattedKerberosPolicy {
  return {
    maxTicketAge: '10 hours',
    maxRenewAge: '7 days',
    maxServiceAge: '600 min',
    maxClockSkew: '5 min',
    ticketValidateClient: true,
    isDefault: true,
  };
}
