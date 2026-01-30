import { Database } from '../core/database';
import Logger from '../core/logger';
import { SystemMetrics } from '../monitoring/system-monitor';
import * as fs from 'fs';
import * as path from 'path';

export interface Detection {
  signature: string;
  name: string;
  description: string;
  severity: string;
  context: any;
  risk_class: string;
}

export interface Exclusions {
  services: string[];
  processes: string[];
  signatures: string[];
}

export class RulesEngine {
  private db: Database;
  private logger: Logger;
  private exclusions: Exclusions = { services: [], processes: [], signatures: [] };
  
  constructor(db: Database, logger: Logger) {
    this.db = db;
    this.logger = logger;
    this.loadExclusions();
  }
  
  private loadExclusions(): void {
    try {
      const exclusionsPath = path.join(process.cwd(), 'config', 'exclusions.json');
      if (fs.existsSync(exclusionsPath)) {
        this.exclusions = JSON.parse(fs.readFileSync(exclusionsPath, 'utf8'));
        this.logger.info('Loaded exclusions', { 
          services: this.exclusions.services.length,
          processes: this.exclusions.processes.length,
          signatures: this.exclusions.signatures.length
        });
      }
    } catch (error: any) {
      this.logger.warn('Failed to load exclusions', { error: error.message });
    }
  }
  
  private isOpticalDrive(drive: string): boolean {
    // Optical drives typically have very small or 0 total size
    // This is a heuristic - DVD drives often show as 0GB or very small
    return drive === 'D:' || drive === 'E:'; // Common DVD drive letters
  }
  
  async evaluate(metrics: SystemMetrics): Promise<Detection[]> {
    // Reload exclusions each time (allows live updates)
    this.loadExclusions();
    
    const detections: Detection[] = [];
    
    // Rule 1: High CPU
    if (metrics.cpu > 90) {
      const topProcess = metrics.processes[0];
      const signature = 'RULE_HIGH_CPU';
      
      // Check if excluded
      if (this.exclusions.signatures.includes(signature)) {
        this.logger.info('Skipping excluded signature', { signature });
      } else if (topProcess && this.exclusions.processes.includes(topProcess.name)) {
        this.logger.info('Skipping excluded process', { process: topProcess.name });
      } else {
        detections.push({
          signature: signature,
          name: 'High CPU Usage',
          description: `CPU at ${metrics.cpu}%`,
          severity: 'high',
          context: { cpu: metrics.cpu, process: topProcess },
          risk_class: 'B'
        });
      }
    }
    
    // Rule 2: Service stopped
    const stoppedServices = metrics.services.filter(s => 
      s.state === 'Stopped' && 
      s.start_type === 'Automatic' &&
      !this.exclusions.services.includes(s.name)
    );
    
    for (const service of stoppedServices) {
      const signature = `RULE_SERVICE_STOPPED_${service.name}`;
      
      if (this.exclusions.signatures.includes(signature)) {
        this.logger.info('Skipping excluded signature', { signature });
        continue;
      }
      
      detections.push({
        signature: signature,
        name: 'Service Stopped',
        description: `${service.display_name} is stopped`,
        severity: 'high',
        context: { service_name: service.name, display_name: service.display_name },
        risk_class: 'A'
      });
    }
    
    // Rule 3: Low disk space (excluding optical drives)
    for (const disk of metrics.disk) {
      // Skip optical drives (DVD/CD)
      if (this.isOpticalDrive(disk.drive)) {
        this.logger.debug('Skipping optical drive', { drive: disk.drive });
        continue;
      }
      
      // Skip drives with 0 or very small total size (likely optical or unmounted)
      if (disk.total_gb < 1) {
        this.logger.debug('Skipping drive with <1GB total', { drive: disk.drive, total_gb: disk.total_gb });
        continue;
      }
      
      if (disk.used_percent > 85) {
        const signature = `RULE_LOW_DISK_${disk.drive}`;
        
        if (this.exclusions.signatures.includes(signature)) {
          this.logger.info('Skipping excluded signature', { signature });
          continue;
        }
        
        detections.push({
          signature: signature,
          name: 'Low Disk Space',
          description: `Drive ${disk.drive}: ${disk.used_percent}% used (${disk.free_gb}GB free)`,
          severity: 'warning',
          context: { drive: disk.drive, used_percent: disk.used_percent, free_gb: disk.free_gb },
          risk_class: 'A'
        });
      }
    }
    
    return detections;
  }
}
