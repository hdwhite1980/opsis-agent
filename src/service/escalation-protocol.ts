import { Logger } from '../common/logger';
import { DeviceSignature } from './signature-generator';
import { RunbookMatch } from './event-monitor';
import { DiagnosticData } from './troubleshooting-runner';

export interface EscalationPayload {
  tenant_id: string;
  device_id: string;
  signature_id: string;
  symptoms: Array<{
    type: string;
    severity: string;
    details: Record<string, any>;
  }>;
  targets: Array<{
    type: string;
    name: string;
    identifier?: string;
  }>;
  baseline_deviation_flags: {
    cpu_deviation: boolean;
    memory_deviation: boolean;
    disk_deviation: boolean;
    service_deviation: boolean;
  };
  environment_tags: {
    os_build: string;
    os_version: string;
    app_versions?: Record<string, string>;
    device_model_class?: string;
  };
  recent_actions_summary: Array<{
    playbook_id: string;
    result_code: 'success' | 'failure' | 'partial';
    timestamp: string;
  }>;
  local_confidence: number;
  requested_outcome: 'recommend_playbook' | 'diagnose_root_cause' | 'needs_approval' | 'needs_outage_correlation';

  // Pre-escalation diagnostic data collected by troubleshooting runbooks
  pre_escalation_diagnostics?: {
    runbook_id: string;
    category: string;
    collected_at: string;
    duration_ms: number;
    data: Record<string, any>;
    partial_failure: boolean;
    errors?: string[];
  };
}

export interface ServerDecision {
  decision_type: 'execute_A' | 'execute_B' | 'request_approval' | 'advisory_only' | 'block' | 'ignore';
  recommended_playbook_id?: string;
  playbook_version?: string;
  parameters?: Record<string, any>;
  confidence_server: number;
  requires_approval: boolean;
  justification_codes: string[];
  verification_requirements?: string[];
  cooldown_override?: boolean;
  approval_token?: string;
  ignore_target?: string;
  ignore_category?: 'services' | 'processes' | 'signatures';
  reason?: string;
  signature_id?: string;
}

export class EscalationProtocol {
  private logger: Logger;
  
  constructor(logger: Logger) {
    this.logger = logger;
  }
  
  buildEscalationPayload(
    signature: DeviceSignature,
    runbook: RunbookMatch | null,
    recentActions: any[],
    diagnosticData?: DiagnosticData | null
  ): EscalationPayload {
    const payload: EscalationPayload = {
      tenant_id: signature.tenant_id,
      device_id: signature.device_id,
      signature_id: signature.signature_id,
      symptoms: signature.symptoms.map(s => ({
        type: s.type,
        severity: s.severity,
        details: this.sanitizeDetails(s.details)
      })),
      targets: signature.targets.map(t => ({
        type: t.type,
        name: t.name,
        identifier: t.identifier
      })),
      baseline_deviation_flags: this.calculateDeviations(signature),
      environment_tags: {
        os_build: signature.context.os_build,
        os_version: signature.context.os_version,
        app_versions: signature.context.app_versions,
        device_model_class: signature.context.device_role
      },
      recent_actions_summary: recentActions.slice(0, 3).map(action => ({
        playbook_id: action.playbook_id,
        result_code: action.result,
        timestamp: action.timestamp
      })),
      local_confidence: signature.confidence_local,
      requested_outcome: this.determineRequestedOutcome(signature, runbook)
    };

    // Include diagnostic data if provided
    if (diagnosticData) {
      payload.pre_escalation_diagnostics = {
        runbook_id: diagnosticData.runbook_id,
        category: diagnosticData.category,
        collected_at: diagnosticData.collected_at,
        duration_ms: diagnosticData.duration_ms,
        data: this.sanitizeDiagnosticData(diagnosticData.data),
        partial_failure: diagnosticData.partial_failure,
        errors: diagnosticData.errors
      };

      this.logger.info('Diagnostic data attached to escalation', {
        signature_id: signature.signature_id,
        runbook_id: diagnosticData.runbook_id,
        category: diagnosticData.category,
        data_keys: Object.keys(diagnosticData.data)
      });
    }

    return payload;
  }

  /**
   * Sanitize diagnostic data to remove sensitive information
   */
  private sanitizeDiagnosticData(data: Record<string, any>): Record<string, any> {
    const sanitized: Record<string, any> = {};

    for (const [key, value] of Object.entries(data)) {
      if (value && typeof value === 'object') {
        // Convert to JSON string, sanitize, then parse back
        let jsonStr = JSON.stringify(value);

        // Redact user paths
        jsonStr = jsonStr.replace(/C:\\\\Users\\\\[^\\\\]+/g, 'C:\\\\Users\\\\<user>');

        // Redact IP addresses (but keep localhost and common network IPs)
        jsonStr = jsonStr.replace(/\b(?!127\.0\.0\.1|0\.0\.0\.0|255\.255\.255\.255|192\.168\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, '<redacted-ip>');

        // Redact tokens (long alphanumeric strings that look like secrets)
        jsonStr = jsonStr.replace(/\b[A-Za-z0-9+/=_\-]{40,}\b/g, '<redacted-token>');

        try {
          sanitized[key] = JSON.parse(jsonStr);
        } catch {
          sanitized[key] = value;
        }
      } else {
        sanitized[key] = value;
      }
    }

    return sanitized;
  }
  
  private sanitizeDetails(details: Record<string, any>): Record<string, any> {
    const sanitized = { ...details };
    
    // Remove potentially sensitive data
    delete sanitized.username;
    delete sanitized.email;
    delete sanitized.domain;
    delete sanitized.sid;
    
    // Redact paths with user info
    if (sanitized.path) {
      sanitized.path = sanitized.path.replace(/C:\\Users\\[^\\]+/g, 'C:\\Users\\<user>');
    }

    // Redact IP addresses
    for (const key of Object.keys(sanitized)) {
      if (typeof sanitized[key] === 'string') {
        sanitized[key] = sanitized[key].replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, '<redacted-ip>');
        // Redact values that look like tokens or passwords (long hex/base64 strings)
        sanitized[key] = sanitized[key].replace(/\b[A-Za-z0-9+/=_\-]{32,}\b/g, '<redacted-token>');
      }
    }

    return sanitized;
  }
  
  private calculateDeviations(signature: DeviceSignature): any {
    return {
      cpu_deviation: signature.symptoms.some(s => s.type === 'performance' && s.details.metric === 'cpu_usage'),
      memory_deviation: signature.symptoms.some(s => s.type === 'performance' && s.details.metric === 'memory_usage'),
      disk_deviation: signature.symptoms.some(s => s.type === 'disk'),
      service_deviation: signature.symptoms.some(s => s.type === 'service_status')
    };
  }
  
  private determineRequestedOutcome(
    signature: DeviceSignature,
    runbook: RunbookMatch | null
  ): EscalationPayload['requested_outcome'] {
    if (!runbook) {
      return 'diagnose_root_cause';
    }
    
    if (signature.confidence_local < 85) {
      return 'recommend_playbook';
    }
    
    if (runbook.steps.some(step => step.requiresApproval)) {
      return 'needs_approval';
    }
    
    return 'recommend_playbook';
  }
}
