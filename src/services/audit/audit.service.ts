/**
 * Main audit service orchestrator
 * TODO: Full implementation in Stories 1.7 and 1.8
 */
export class AuditService {
  async runAudit(
    provider: 'active-directory' | 'azure',
    _options: unknown
  ): Promise<unknown> {
    throw new Error(`${provider} audit not implemented yet`);
  }
}
