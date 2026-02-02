/**
 * Export Controller
 *
 * Handles audit result export operations.
 * Story 1.10: API Controllers & Routes
 *
 * Endpoints:
 * - POST /api/v1/audit/ad/export - Export AD audit results
 * - POST /api/v1/audit/azure/export - Export Azure audit results
 */

import { Request, Response, NextFunction } from 'express';
import { ExportService, ExportAuditResult } from '../../services/export/export.service';
import { JSONExportOptions } from '../../services/export/formatters/json.formatter';
import { CSVExportOptions } from '../../services/export/formatters/csv.formatter';

/**
 * Export format
 */
type ExportFormat = 'json' | 'csv';

/**
 * AD Export request body
 */
interface ADExportRequest {
  auditResult: ExportAuditResult;
  format: ExportFormat;
  domain?: string;
  includeDetails?: boolean;
  includeAffectedEntities?: boolean;
  delimiter?: string;
}

/**
 * Azure Export request body
 */
interface AzureExportRequest {
  auditResult: ExportAuditResult;
  format: ExportFormat;
  tenantId?: string;
  includeDetails?: boolean;
  includeAffectedEntities?: boolean;
  delimiter?: string;
}

/**
 * Export Controller
 */
export class ExportController {
  private exportService: ExportService;

  constructor() {
    this.exportService = new ExportService();
  }

  /**
   * Export AD audit results
   *
   * POST /api/v1/audit/ad/export
   */
  async exportADAudit(
    req: Request<object, object, ADExportRequest>,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const { auditResult, format, domain, includeDetails, includeAffectedEntities, delimiter } = req.body;

      let result;

      if (format === 'json') {
        // Export as JSON
        const options: JSONExportOptions = {
          provider: 'ad',
          domain,
          includeDetails,
        };
        result = this.exportService.exportToJSON(auditResult, options);
      } else if (format === 'csv') {
        // Export as CSV
        const options: CSVExportOptions = {
          includeAffectedEntities,
          delimiter,
        };
        result = this.exportService.exportToCSV(auditResult, 'ad', domain || 'unknown', options);
      } else {
        res.status(400).json({
          success: false,
          error: 'Invalid format. Must be "json" or "csv".',
        });
        return;
      }

      // Set headers
      res.setHeader('Content-Type', result.contentType);
      res.setHeader('Content-Disposition', result.contentDisposition);

      // Send content
      res.send(result.content);
    } catch (error) {
      next(error);
    }
  }

  /**
   * Export Azure audit results
   *
   * POST /api/v1/audit/azure/export
   */
  async exportAzureAudit(
    req: Request<object, object, AzureExportRequest>,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const { auditResult, format, tenantId, includeDetails, includeAffectedEntities, delimiter } = req.body;

      let result;

      if (format === 'json') {
        // Export as JSON
        const options: JSONExportOptions = {
          provider: 'azure',
          tenantId,
          includeDetails,
        };
        result = this.exportService.exportToJSON(auditResult, options);
      } else if (format === 'csv') {
        // Export as CSV
        const options: CSVExportOptions = {
          includeAffectedEntities,
          delimiter,
        };
        result = this.exportService.exportToCSV(auditResult, 'azure', tenantId || 'unknown', options);
      } else {
        res.status(400).json({
          success: false,
          error: 'Invalid format. Must be "json" or "csv".',
        });
        return;
      }

      // Set headers
      res.setHeader('Content-Type', result.contentType);
      res.setHeader('Content-Disposition', result.contentDisposition);

      // Send content
      res.send(result.content);
    } catch (error) {
      next(error);
    }
  }
}
