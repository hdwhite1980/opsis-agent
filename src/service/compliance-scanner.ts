// compliance-scanner.ts - Framework-agnostic compliance scanning service
// Receives templates from server, runs PowerShell checks, detects drift, triggers enforcement
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { Logger } from '../common/logger';
import { securePowerShell } from '../execution/primitives/index';
import {
  ComplianceCheck,
  ComplianceTemplate,
  ComplianceCheckResult,
  ComplianceDriftEvent,
  ComplianceReport,
  ComplianceScanData,
} from './compliance-scanner-types';

const DEFAULT_SCAN_INTERVAL_MINUTES = 15;
const STARTUP_DELAY_MS = 30000;
const DEFAULT_CHECK_TIMEOUT_MS = 30000;

export type ComplianceReportCallback = (report: ComplianceReport) => void;
export type ComplianceDriftCallback = (drifts: ComplianceDriftEvent[]) => void;
export type ComplianceEnforcementCallback = (check: ComplianceCheck) => Promise<{ success: boolean; error?: string }>;
export type ComplianceSendCallback = (message: any) => boolean;

export class ComplianceScanner {
  private logger: Logger;
  private dataDir: string;
  private templatePath: string;
  private resultsPath: string;
  private pendingReportsPath: string;

  private template: ComplianceTemplate | null = null;
  private lastResults: Record<string, ComplianceCheckResult> = {};
  private pendingReports: any[] = [];

  private scanTimer: NodeJS.Timeout | null = null;
  private startupTimer: NodeJS.Timeout | null = null;
  private isScanning = false;

  private deviceId = '';
  private tenantId = '';

  private onReportReady: ComplianceReportCallback | null = null;
  private onDriftDetected: ComplianceDriftCallback | null = null;
  private onEnforcementNeeded: ComplianceEnforcementCallback | null = null;
  private onSend: ComplianceSendCallback | null = null;

  constructor(logger: Logger, dataDir: string) {
    this.logger = logger;
    this.dataDir = dataDir;
    this.templatePath = path.join(dataDir, 'compliance-template.json');
    this.resultsPath = path.join(dataDir, 'compliance-results.json');
    this.pendingReportsPath = path.join(dataDir, 'pending-compliance-reports.json');
  }

  setDeviceInfo(deviceId: string, tenantId: string): void {
    this.deviceId = deviceId;
    this.tenantId = tenantId;
  }

  setReportCallback(cb: ComplianceReportCallback): void {
    this.onReportReady = cb;
  }

  setDriftCallback(cb: ComplianceDriftCallback): void {
    this.onDriftDetected = cb;
  }

  setEnforcementCallback(cb: ComplianceEnforcementCallback): void {
    this.onEnforcementNeeded = cb;
  }

  setSendCallback(cb: ComplianceSendCallback): void {
    this.onSend = cb;
  }

  // ============================
  // LIFECYCLE
  // ============================

  async start(): Promise<void> {
    this.logger.info('Compliance scanner starting');

    // Load template from disk (for offline operation)
    this.template = this.loadTemplate();

    // Load last results from disk (for drift detection across restarts)
    const scanData = this.loadResults();
    if (scanData) {
      this.lastResults = scanData.last_results;
    }

    // Load pending reports queue
    this.pendingReports = this.loadPendingReports();

    if (this.template) {
      this.logger.info('Compliance template loaded from disk', {
        template_id: this.template.template_id,
        version: this.template.template_version,
        checks: this.template.checks.length,
      });
      this.scheduleScans(this.template.scan_interval_minutes || DEFAULT_SCAN_INTERVAL_MINUTES);
    } else {
      this.logger.info('No compliance template configured — waiting for server to push one');
    }
  }

  stop(): void {
    if (this.scanTimer) {
      clearInterval(this.scanTimer);
      this.scanTimer = null;
    }
    if (this.startupTimer) {
      clearTimeout(this.startupTimer);
      this.startupTimer = null;
    }
    this.logger.info('Compliance scanner stopped');
  }

  // ============================
  // TEMPLATE MANAGEMENT
  // ============================

  updateTemplate(template: ComplianceTemplate): void {
    this.logger.info('Compliance template updated', {
      template_id: template.template_id,
      version: template.template_version,
      checks: template.checks.length,
      scan_interval: template.scan_interval_minutes,
    });

    this.template = template;
    this.saveTemplate(template);

    // Reschedule with new interval
    this.stop();
    this.scheduleScans(template.scan_interval_minutes || DEFAULT_SCAN_INTERVAL_MINUTES);
  }

  getTemplate(): ComplianceTemplate | null {
    return this.template;
  }

  // ============================
  // SCHEDULING
  // ============================

  private scheduleScans(intervalMinutes: number): void {
    const intervalMs = intervalMinutes * 60 * 1000;

    // Initial scan with startup delay
    this.startupTimer = setTimeout(() => {
      this.runScan().catch(err =>
        this.logger.error('Initial compliance scan failed', err)
      );
    }, STARTUP_DELAY_MS);

    // Recurring scans
    this.scanTimer = setInterval(() => {
      this.runScan().catch(err =>
        this.logger.error('Scheduled compliance scan failed', err)
      );
    }, intervalMs);

    this.logger.info('Compliance scans scheduled', {
      interval_minutes: intervalMinutes,
      startup_delay_ms: STARTUP_DELAY_MS,
    });
  }

  // ============================
  // SCAN EXECUTION
  // ============================

  async runScan(): Promise<ComplianceReport> {
    if (this.isScanning) {
      this.logger.warn('Compliance scan already in progress, skipping');
      return this.buildEmptyReport();
    }

    if (!this.template) {
      this.logger.warn('No compliance template loaded, skipping scan');
      return this.buildEmptyReport();
    }

    this.isScanning = true;
    const scanStartedAt = new Date().toISOString();
    const startTime = Date.now();
    const reportId = crypto.randomBytes(8).toString('hex');

    this.logger.info('Starting compliance scan', {
      template_id: this.template.template_id,
      checks: this.template.checks.length,
    });

    try {
      const results: ComplianceCheckResult[] = [];
      const driftEvents: ComplianceDriftEvent[] = [];

      for (const check of this.template.checks) {
        const result = await this.executeCheck(check);
        results.push(result);

        // Detect drift against last scan
        const drift = this.detectDrift(check, result);
        if (drift) {
          driftEvents.push(drift);
        }
      }

      // Fire drift alerts immediately (don't wait for report)
      if (driftEvents.length > 0 && this.onDriftDetected) {
        this.onDriftDetected(driftEvents);
      }

      // Build report
      const scanCompletedAt = new Date().toISOString();
      const report = this.buildReport(
        reportId, this.template, results, driftEvents,
        scanStartedAt, scanCompletedAt, Date.now() - startTime
      );

      // Update last results for next drift comparison
      this.lastResults = {};
      for (const r of results) {
        this.lastResults[r.check_id] = r;
      }
      this.saveResults({
        last_results: this.lastResults,
        last_scan_at: scanCompletedAt,
        last_report_id: reportId,
      });

      // Fire report callback
      if (this.onReportReady) {
        this.onReportReady(report);
      }

      this.logger.info('Compliance scan complete', {
        report_id: reportId,
        compliance: report.compliance_percentage.toFixed(1) + '%',
        passed: report.passed,
        failed: report.failed,
        errors: report.errors,
        drift_events: driftEvents.length,
        enforcements: report.enforcements_attempted,
        duration_ms: report.scan_duration_ms,
      });

      return report;
    } finally {
      this.isScanning = false;
    }
  }

  // ============================
  // CHECK EXECUTION
  // ============================

  private async executeCheck(check: ComplianceCheck): Promise<ComplianceCheckResult> {
    const startTime = Date.now();

    try {
      const timeout = check.timeout_ms || DEFAULT_CHECK_TIMEOUT_MS;
      const result = securePowerShell(check.command, { timeout });

      if (!result.success) {
        return {
          check_id: check.check_id,
          name: check.name,
          category: check.category,
          severity: check.severity,
          status: 'error',
          expected_value: check.expected_value,
          actual_value: '',
          mode: check.mode,
          enforcement_attempted: false,
          duration_ms: Date.now() - startTime,
          error_message: result.stderr ? result.stderr.substring(0, 200) : 'PowerShell execution failed',
        };
      }

      const actualValue = result.stdout.trim();
      const passed = this.compareValue(actualValue, check.expected_value, check.comparison);

      const checkResult: ComplianceCheckResult = {
        check_id: check.check_id,
        name: check.name,
        category: check.category,
        severity: check.severity,
        status: passed ? 'pass' : 'fail',
        expected_value: check.expected_value,
        actual_value: actualValue,
        mode: check.mode,
        enforcement_attempted: false,
        duration_ms: Date.now() - startTime,
      };

      // Enforce if check failed and mode is enforce
      if (!passed && check.mode === 'enforce' && this.onEnforcementNeeded) {
        checkResult.enforcement_attempted = true;

        const enforcementResult = await this.onEnforcementNeeded(check);

        if (enforcementResult.error?.startsWith('dampened:')) {
          checkResult.enforcement_result = 'dampened';
          checkResult.enforcement_error = enforcementResult.error;
        } else if (enforcementResult.success) {
          checkResult.enforcement_result = 'success';
          checkResult.post_enforcement_status = 'pass';
          // Update the result status since enforcement fixed it
          checkResult.status = 'pass';
          checkResult.actual_value = check.expected_value;
        } else {
          checkResult.enforcement_result = 'failure';
          checkResult.enforcement_error = enforcementResult.error;
          checkResult.post_enforcement_status = 'fail';
        }
      }

      checkResult.duration_ms = Date.now() - startTime;
      return checkResult;
    } catch (err: any) {
      return {
        check_id: check.check_id,
        name: check.name,
        category: check.category,
        severity: check.severity,
        status: 'error',
        expected_value: check.expected_value,
        actual_value: '',
        mode: check.mode,
        enforcement_attempted: false,
        duration_ms: Date.now() - startTime,
        error_message: err.message?.substring(0, 200) || 'Unknown error',
      };
    }
  }

  // ============================
  // COMPARISON
  // ============================

  compareValue(actual: string, expected: string, comparison: ComplianceCheck['comparison']): boolean {
    const a = actual.trim();
    const e = expected.trim();

    switch (comparison) {
      case 'equals':
        return a === e;
      case 'not_equals':
        return a !== e;
      case 'contains':
        return a.includes(e);
      case 'regex':
        try {
          return new RegExp(e).test(a);
        } catch {
          return false;
        }
      case 'greater_than':
        return parseFloat(a) > parseFloat(e);
      case 'less_than':
        return parseFloat(a) < parseFloat(e);
      default:
        return a === e;
    }
  }

  // ============================
  // DRIFT DETECTION
  // ============================

  private detectDrift(check: ComplianceCheck, currentResult: ComplianceCheckResult): ComplianceDriftEvent | null {
    const prev = this.lastResults[check.check_id];
    if (!prev) return null;

    // Only track pass<->fail transitions
    if (prev.status === 'pass' && currentResult.status === 'fail') {
      return {
        check_id: check.check_id,
        name: check.name,
        category: check.category,
        severity: check.severity,
        drift_type: 'pass_to_fail',
        previous_status: 'pass',
        current_status: 'fail',
        previous_value: prev.actual_value,
        current_value: currentResult.actual_value,
        detected_at: new Date().toISOString(),
      };
    }

    if (prev.status === 'fail' && currentResult.status === 'pass') {
      return {
        check_id: check.check_id,
        name: check.name,
        category: check.category,
        severity: check.severity,
        drift_type: 'fail_to_pass',
        previous_status: 'fail',
        current_status: 'pass',
        previous_value: prev.actual_value,
        current_value: currentResult.actual_value,
        detected_at: new Date().toISOString(),
      };
    }

    return null;
  }

  // ============================
  // REPORT BUILDING
  // ============================

  private buildReport(
    reportId: string,
    template: ComplianceTemplate,
    results: ComplianceCheckResult[],
    driftEvents: ComplianceDriftEvent[],
    scanStartedAt: string,
    scanCompletedAt: string,
    durationMs: number,
  ): ComplianceReport {
    const passed = results.filter(r => r.status === 'pass').length;
    const failed = results.filter(r => r.status === 'fail').length;
    const errors = results.filter(r => r.status === 'error').length;
    const skipped = results.filter(r => r.status === 'skipped').length;

    const gradeable = passed + failed;
    const compliancePercentage = gradeable > 0 ? (passed / gradeable) * 100 : 0;

    const enforced = results.filter(r => r.enforcement_attempted);

    return {
      report_id: reportId,
      template_id: template.template_id,
      template_version: template.template_version,
      template_name: template.name,
      device_id: this.deviceId,
      tenant_id: this.tenantId,
      scan_started_at: scanStartedAt,
      scan_completed_at: scanCompletedAt,
      scan_duration_ms: durationMs,

      total_checks: results.length,
      passed,
      failed,
      errors,
      skipped,
      compliance_percentage: Math.round(compliancePercentage * 10) / 10,

      enforcements_attempted: enforced.length,
      enforcements_succeeded: enforced.filter(r => r.enforcement_result === 'success').length,
      enforcements_failed: enforced.filter(r => r.enforcement_result === 'failure').length,
      enforcements_dampened: enforced.filter(r => r.enforcement_result === 'dampened').length,

      drift_events: driftEvents,
      results,
    };
  }

  private buildEmptyReport(): ComplianceReport {
    return {
      report_id: '',
      template_id: '',
      template_version: '',
      template_name: '',
      device_id: this.deviceId,
      tenant_id: this.tenantId,
      scan_started_at: new Date().toISOString(),
      scan_completed_at: new Date().toISOString(),
      scan_duration_ms: 0,
      total_checks: 0,
      passed: 0,
      failed: 0,
      errors: 0,
      skipped: 0,
      compliance_percentage: 0,
      enforcements_attempted: 0,
      enforcements_succeeded: 0,
      enforcements_failed: 0,
      enforcements_dampened: 0,
      drift_events: [],
      results: [],
    };
  }

  // ============================
  // OFFLINE REPORT QUEUING
  // ============================

  queuePendingReport(message: any): void {
    this.pendingReports.push(message);
    this.savePendingReports();
  }

  flushPendingReports(): void {
    if (this.pendingReports.length === 0) return;
    if (!this.onSend) return;

    const queued = [...this.pendingReports];
    this.pendingReports = [];
    let sent = 0;

    for (const message of queued) {
      if (this.onSend(message)) {
        sent++;
      } else {
        this.pendingReports.push(message);
      }
    }

    this.savePendingReports();
    this.logger.info('Flushed pending compliance reports', {
      sent,
      remaining: this.pendingReports.length,
    });
  }

  // ============================
  // PERSISTENCE
  // ============================

  private loadTemplate(): ComplianceTemplate | null {
    try {
      if (fs.existsSync(this.templatePath)) {
        return JSON.parse(fs.readFileSync(this.templatePath, 'utf8'));
      }
    } catch (err) {
      this.logger.warn('Failed to load compliance template', err);
    }
    return null;
  }

  private saveTemplate(template: ComplianceTemplate): void {
    try {
      fs.writeFileSync(this.templatePath, JSON.stringify(template, null, 2), 'utf8');
    } catch (err) {
      this.logger.error('Failed to save compliance template', err);
    }
  }

  private loadResults(): ComplianceScanData | null {
    try {
      if (fs.existsSync(this.resultsPath)) {
        return JSON.parse(fs.readFileSync(this.resultsPath, 'utf8'));
      }
    } catch (err) {
      this.logger.warn('Failed to load compliance results', err);
    }
    return null;
  }

  private saveResults(data: ComplianceScanData): void {
    try {
      fs.writeFileSync(this.resultsPath, JSON.stringify(data, null, 2), 'utf8');
    } catch (err) {
      this.logger.error('Failed to save compliance results', err);
    }
  }

  private loadPendingReports(): any[] {
    try {
      if (fs.existsSync(this.pendingReportsPath)) {
        const data = JSON.parse(fs.readFileSync(this.pendingReportsPath, 'utf8'));
        if (Array.isArray(data)) {
          this.logger.info('Loaded pending compliance reports from disk', { count: data.length });
          return data;
        }
      }
    } catch (err) {
      this.logger.warn('Failed to load pending compliance reports', err);
    }
    return [];
  }

  private savePendingReports(): void {
    try {
      fs.writeFileSync(this.pendingReportsPath, JSON.stringify(this.pendingReports, null, 2), 'utf8');
    } catch (err) {
      this.logger.error('Failed to save pending compliance reports', err);
    }
  }
}
