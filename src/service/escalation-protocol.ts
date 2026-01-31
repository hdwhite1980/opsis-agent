import { Logger } from '../common/logger';
import { DeviceSignature } from './signature-generator';
import { RunbookMatch } from './event-monitor';

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
    recentActions: any[]
  ): EscalationPayload {
    return {
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
