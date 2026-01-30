import { SystemMetrics } from '../types';
import Logger from '../core/logger';

export interface RuleResult {
  triggered: boolean;
  signature_id: string;
  signature_name: string;
  confidence: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  affected_component?: string;
  recommended_action?: string;
  candidate_playbooks?: string[];
  risk_class: 'A' | 'B' | 'C';
}

export class ExpertRulesEngine {
  private logger: Logger;
  
  constructor(logger: Logger) {
    this.logger = logger;
  }
  
  evaluateRules(metrics: SystemMetrics): RuleResult[] {
    const results: RuleResult[] = [];
    
    // Rule 1: High CPU (sustained)
    if (metrics.cpu.usage_percent >= 90 && metrics.cpu.duration_seconds >= 300) {
      results.push({
        triggered: true,
        signature_id: 'RULE_CPU_HIGH_SUSTAINED',
        signature_name: 'High CPU Usage (Sustained)',
        confidence: 95,
        severity: 'high',
        description: `CPU at ${metrics.cpu.usage_percent}% for ${metrics.cpu.duration_seconds} seconds`,
        affected_component: 'CPU',
        recommended_action: 'Identify and terminate resource-intensive process',
        candidate_playbooks: ['cpu_high_kill_process', 'cpu_high_restart_service'],
        risk_class: 'A'
      });
    }
    
    // Rule 2: Critical CPU (immediate)
    if (metrics.cpu.usage_percent >= 95) {
      results.push({
        triggered: true,
        signature_id: 'RULE_CPU_CRITICAL',
        signature_name: 'Critical CPU Usage',
        confidence: 98,
        severity: 'critical',
        description: `CPU at ${metrics.cpu.usage_percent}% - system unresponsive risk`,
        affected_component: 'CPU',
        recommended_action: 'Immediate process termination required',
        candidate_playbooks: ['cpu_critical_emergency_kill'],
        risk_class: 'A'
      });
    }
    
    // Rule 3: High memory usage
    if (metrics.memory.usage_percent >= 90) {
      results.push({
        triggered: true,
        signature_id: 'RULE_MEMORY_HIGH',
        signature_name: 'High Memory Usage',
        confidence: 92,
        severity: 'high',
        description: `Memory at ${metrics.memory.usage_percent}% (${metrics.memory.used_mb}MB / ${metrics.memory.total_mb}MB)`,
        affected_component: 'Memory',
        recommended_action: 'Identify memory leak or restart memory-intensive service',
        candidate_playbooks: ['memory_high_clear_cache', 'memory_high_restart_service'],
        risk_class: 'B'
      });
    }
    
    // Rule 4: Low disk space
    for (const drive of metrics.disk.drives) {
      if (drive.free_percent < 10) {
        results.push({
          triggered: true,
          signature_id: `RULE_DISK_LOW_${drive.letter}`,
          signature_name: `Low Disk Space (${drive.letter})`,
          confidence: 97,
          severity: drive.free_percent < 5 ? 'critical' : 'high',
          description: `Drive ${drive.letter} has only ${drive.free_gb}GB free (${drive.free_percent}%)`,
          affected_component: `Disk ${drive.letter}`,
          recommended_action: 'Run disk cleanup, clear temp files, or remove old logs',
          candidate_playbooks: ['disk_cleanup_temp', 'disk_cleanup_logs', 'disk_cleanup_recycle_bin'],
          risk_class: 'A'
        });
      }
    }
    
    // Rule 5: Critical services stopped
    const criticalServices = [
      'wuauserv',      // Windows Update
      'W32Time',       // Windows Time
      'Dnscache',      // DNS Client
      'BITS',          // Background Intelligent Transfer Service
      'EventLog'       // Windows Event Log
    ];
    
    for (const service of metrics.services) {
      if (criticalServices.some(s => s.toLowerCase() === service.name.toLowerCase()) && service.state === 'stopped' && service.start_type === 'auto') {
        results.push({
          triggered: true,
          signature_id: `RULE_SERVICE_STOPPED_${service.name}`,
          signature_name: `Critical Service Stopped: ${service.display_name}`,
          confidence: 96,
          severity: 'high',
          description: `Service "${service.display_name}" (${service.name}) is stopped but should be running`,
          affected_component: service.name,
          recommended_action: `Restart ${service.display_name} service`,
          candidate_playbooks: [`service_restart_${service.name}`, 'service_restart_generic'],
          risk_class: 'A'
        });
      }
    }
    
    // Rule 6: Single process consuming excessive CPU
    const topProcess = metrics.cpu.top_processes[0];
    if (topProcess && topProcess.cpu_percent >= 80) {
      results.push({
        triggered: true,
        signature_id: 'RULE_PROCESS_CPU_HOG',
        signature_name: 'Process Consuming Excessive CPU',
        confidence: 93,
        severity: 'medium',
        description: `Process "${topProcess.name}" (PID ${topProcess.pid}) consuming ${topProcess.cpu_percent}% CPU`,
        affected_component: topProcess.name,
        recommended_action: `Terminate or restart process ${topProcess.name}`,
        candidate_playbooks: ['process_kill_by_name', 'process_restart_by_name'],
        risk_class: 'B'
      });
    }
    
    // Rule 7: Memory leak detection (single process using >4GB)
    for (const process of metrics.processes) {
      if (process.memory_mb >= 4096) {
        results.push({
          triggered: true,
          signature_id: 'RULE_MEMORY_LEAK_SUSPECTED',
          signature_name: 'Possible Memory Leak Detected',
          confidence: 85,
          severity: 'medium',
          description: `Process "${process.name}" (PID ${process.pid}) using ${process.memory_mb}MB memory`,
          affected_component: process.name,
          recommended_action: `Investigate and possibly restart ${process.name}`,
          candidate_playbooks: ['process_restart_by_name'],
          risk_class: 'C'
        });
      }
    }
    
    if (results.length > 0) {
      this.logger.info(`Rules engine detected ${results.length} issue(s)`, {
        signatures: results.map(r => r.signature_id)
      });
    }
    
    return results;
  }
  
  // Get highest confidence result
  getBestMatch(results: RuleResult[]): RuleResult | null {
    if (results.length === 0) return null;
    return results.sort((a, b) => b.confidence - a.confidence)[0];
  }
}

