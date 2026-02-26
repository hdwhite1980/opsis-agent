// compliance-scanner-types.ts - Type definitions for Compliance Scanner service

// ============================
// COMPLIANCE TEMPLATE (server-pushed)
// ============================

export interface ComplianceCheck {
  check_id: string;
  name: string;
  description: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low';

  // Check definition
  command: string;                     // PowerShell script to run
  expected_value: string;              // Expected output
  comparison: 'equals' | 'not_equals' | 'contains' | 'regex' | 'greater_than' | 'less_than';
  timeout_ms?: number;                 // Per-check timeout (default 30s)

  // Enforcement
  mode: 'audit' | 'enforce';
  remediation_command?: string;        // PowerShell to fix (required when mode=enforce)
  remediation_timeout_ms?: number;     // Timeout for remediation (default 60s)
}

export interface ComplianceTemplate {
  template_id: string;
  template_version: string;
  name: string;
  description: string;
  pushed_at: string;
  scan_interval_minutes: number;
  checks: ComplianceCheck[];
}

// ============================
// CHECK RESULTS
// ============================

export interface ComplianceCheckResult {
  check_id: string;
  name: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'pass' | 'fail' | 'error' | 'skipped';
  expected_value: string;
  actual_value: string;
  mode: 'audit' | 'enforce';

  // Enforcement details (populated when mode=enforce and status=fail)
  enforcement_attempted: boolean;
  enforcement_result?: 'success' | 'failure' | 'dampened';
  enforcement_error?: string;
  post_enforcement_status?: 'pass' | 'fail' | 'error';

  duration_ms: number;
  error_message?: string;
}

// ============================
// DRIFT EVENTS
// ============================

export interface ComplianceDriftEvent {
  check_id: string;
  name: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  drift_type: 'pass_to_fail' | 'fail_to_pass';
  previous_status: 'pass' | 'fail';
  current_status: 'pass' | 'fail';
  previous_value: string;
  current_value: string;
  detected_at: string;
}

// ============================
// COMPLIANCE REPORT
// ============================

export interface ComplianceReport {
  report_id: string;
  template_id: string;
  template_version: string;
  template_name: string;
  device_id: string;
  tenant_id: string;
  scan_started_at: string;
  scan_completed_at: string;
  scan_duration_ms: number;

  // Summary
  total_checks: number;
  passed: number;
  failed: number;
  errors: number;
  skipped: number;
  compliance_percentage: number;

  // Enforcement summary
  enforcements_attempted: number;
  enforcements_succeeded: number;
  enforcements_failed: number;
  enforcements_dampened: number;

  // Drift
  drift_events: ComplianceDriftEvent[];

  // Full results
  results: ComplianceCheckResult[];
}

// ============================
// PERSISTENCE
// ============================

export interface ComplianceScanData {
  last_results: Record<string, ComplianceCheckResult>;
  last_scan_at: string;
  last_report_id: string;
}
