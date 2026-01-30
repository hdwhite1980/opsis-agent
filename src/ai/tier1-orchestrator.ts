import Logger from '../core/logger';

export interface Tier1Analysis {
  confidence: number;
  should_escalate: boolean;
  escalation_reason?: string;
  recommended_playbooks: string[];
}

export class Tier1Orchestrator {
  private logger: Logger;
  
  constructor(logger: Logger) {
    this.logger = logger;
  }
  
  async analyze(detection: any): Promise<Tier1Analysis> {
    const playbooks: string[] = [];
    let confidence = 95;
    
    if (detection.signature.startsWith('RULE_SERVICE_STOPPED_')) {
      const serviceName = detection.context.service_name;
      playbooks.push(`service_restart_${serviceName}`);
      playbooks.push('service_restart_generic');
    } else if (detection.signature.startsWith('RULE_LOW_DISK_')) {
      playbooks.push('disk_cleanup_comprehensive');
    } else if (detection.signature === 'RULE_HIGH_CPU') {
      const processName = detection.context.process?.name;
      if (processName) {
        playbooks.push(`process_kill_${processName}`);
      }
      confidence = 70;
    }
    
    return {
      confidence,
      should_escalate: playbooks.length === 0,
      escalation_reason: playbooks.length === 0 ? 'No playbooks available' : undefined,
      recommended_playbooks: playbooks
    };
  }
}
