// Type definitions

export interface SystemMetrics {
  timestamp: number;
  cpu: {
    usage_percent: number;
    duration_seconds: number;
    top_processes: Process[];
  };
  memory: {
    total_mb: number;
    available_mb: number;
    used_mb: number;
    usage_percent: number;
  };
  disk: {
    drives: DiskDrive[];
  };
  services: Service[];
  processes: Process[];
}

export interface Process {
  name: string;
  pid: number;
  cpu_percent: number;
  memory_mb: number;
}

export interface Service {
  name: string;
  display_name: string;
  state: 'running' | 'stopped' | 'paused';
  start_type: 'auto' | 'manual' | 'disabled';
}

export interface DiskDrive {
  letter: string;
  total_gb: number;
  free_gb: number;
  free_percent: number;
}

export interface Tier1Result {
  source: 'rule' | 'ml' | 'baseline';
  signature_id: string;
  signature_name: string;
  confidence: number;
  is_issue: boolean;
  should_escalate: boolean;
  candidate_playbooks: Array<{
    playbook_id: string;
    rank: number;
    score: number;
  }>;
  risk_class: 'A' | 'B' | 'C';
}

export interface AutoRemediationTicket {
  ticket_id: string;
  tenant_id: string;
  device_id: string;
  device_group?: string;
  timestamp_created: number;
  timestamp_completed?: number;
  actor: 'OPSIS_AGENT';
  
  action_type: string;
  action_target: any;
  
  playbook_id: string;
  playbook_version: string;
  
  signature_id: string;
  risk_class: 'A' | 'B' | 'C';
  
  result?: 'success' | 'failed' | 'rollback' | 'partial' | 'escalated';
  verification_status?: {
    status: 'pass' | 'fail';
    reason_code?: string;
    details?: string;
  };
  
  user_impact: 'none' | 'app_restart' | 'brief_disconnect' | 'service_restart' | 'reboot';
  
  precheck_snapshot?: {
    cpu_bucket: string;
    memory_bucket: string;
    disk_free_bucket: string;
    network_state: 'connected' | 'disconnected';
  };
  
  duration_ms?: number;
  correlation_id?: string;
  next_recommended_step?: string;
  
  tier1_confidence?: number;
  tier1_source?: 'rule' | 'ml';
  escalated?: boolean;
}
