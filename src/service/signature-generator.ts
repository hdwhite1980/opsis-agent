import crypto from 'crypto';
import * as os from 'os';
import { Logger } from '../common/logger';
import { EventLogEntry } from './event-monitor';
import { SystemSignal } from './system-monitor';

export interface Symptom {
  type: 'event_log' | 'service_status' | 'performance' | 'network' | 'process' | 'disk';
  severity: 'low' | 'medium' | 'high' | 'critical';
  details: Record<string, any>;
}

export interface Target {
  type: 'service' | 'process' | 'application' | 'system' | 'network';
  name: string;
  identifier?: string; // PID, service name, etc.
}

export interface SignatureContext {
  os_build: string;
  os_version: string;
  app_versions?: Record<string, string>;
  device_role?: string;
  uptime_bucket?: string;
}

export interface DeviceSignature {
  signature_id: string;
  symptoms: Symptom[];
  targets: Target[];
  context: SignatureContext;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence_local: number;
  timestamp: string;
  device_id: string;
  tenant_id: string;
}

export class SignatureGenerator {
  private logger: Logger;
  
  constructor(logger: Logger) {
    this.logger = logger;
  }
  
  generateFromEvent(event: EventLogEntry, deviceInfo: any): DeviceSignature {
    const symptoms: Symptom[] = [{
      type: 'event_log',
      severity: this.mapEventLevelToSeverity(event.level),
      details: {
        event_id: event.id,
        source: event.source,
        log_name: event.logName,
        message_pattern: this.extractMessagePattern(event.message)
      }
    }];
    
    const targets: Target[] = this.extractTargetsFromEvent(event);
    const context = this.buildContext(deviceInfo);
    
    const signatureData = {
      symptoms,
      targets,
      context,
      event_id: event.id
    };
    
    const signature_id = this.generateHash(signatureData);
    
    return {
      signature_id,
      symptoms,
      targets,
      context,
      severity: this.calculateOverallSeverity(symptoms),
      confidence_local: this.calculateConfidence(event, targets),
      timestamp: new Date().toISOString(),
      device_id: deviceInfo.device_id,
      tenant_id: deviceInfo.tenant_id
    };
  }
  
  generateFromSystemSignal(signal: SystemSignal, deviceInfo: any): DeviceSignature {
    const symptoms: Symptom[] = [{
      type: this.mapSignalCategory(signal.category),
      severity: this.mapSystemSignalSeverity(signal.severity), // Fixed: map 'warning'/'info' to our severity types
      details: {
        metric: signal.metric,
        value: signal.value,
        threshold: signal.threshold,
        ...(signal.details || {}),
        metadata: signal.metadata
      }
    }];
    
    const targets: Target[] = this.extractTargetsFromSignal(signal);
    const context = this.buildContext(deviceInfo);

    // Build stable hash input: exclude volatile values (metric reading, PIDs, uptime_bucket)
    // so the same logical condition always produces the same signature_id
    const stableSignatureData = {
      symptoms: [{
        type: this.mapSignalCategory(signal.category),
        severity: this.mapSystemSignalSeverity(signal.severity),
        details: {
          metric: signal.metric,
          threshold: signal.threshold
        }
      }],
      targets: targets.map(t => ({ type: t.type, name: t.name })),
      context: {
        os_build: context.os_build,
        os_version: context.os_version,
        device_role: context.device_role
      },
      signal_category: signal.category
    };

    const signature_id = this.generateHash(stableSignatureData);
    
    return {
      signature_id,
      symptoms,
      targets,
      context,
      severity: this.mapSystemSignalSeverity(signal.severity), // Fixed: map signal severity
      confidence_local: this.calculateSignalConfidence(signal),
      timestamp: new Date().toISOString(),
      device_id: deviceInfo.device_id,
      tenant_id: deviceInfo.tenant_id
    };
  }
  
  private generateHash(data: any): string {
    const normalized = JSON.stringify(data, Object.keys(data).sort());
    return crypto.createHash('sha256').update(normalized).digest('hex').substring(0, 32);
  }
  
  private extractMessagePattern(message: string): string {
    return message
      .replace(/\b[A-Z]:\\.+?\b/g, '<path>')
      .replace(/\b\d+\b/g, '<num>')
      .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, '<guid>')
      .substring(0, 200);
  }
  
  private extractTargetsFromEvent(event: EventLogEntry): Target[] {
    const targets: Target[] = [];
    
    const serviceMatch = event.message.match(/service\s+['""]?([a-zA-Z0-9_\s-]+)['""]?/i);
    if (serviceMatch) {
      targets.push({
        type: 'service',
        name: serviceMatch[1].trim()
      });
    }
    
    const processMatch = event.message.match(/([a-zA-Z0-9_-]+\.exe)/i);
    if (processMatch) {
      targets.push({
        type: 'process',
        name: processMatch[1]
      });
    }
    
    return targets;
  }
  
  private extractTargetsFromSignal(signal: SystemSignal): Target[] {
    const targets: Target[] = [];
    
    if (signal.metadata?.serviceName) {
      targets.push({
        type: 'service',
        name: signal.metadata.serviceName
      });
    }
    
    if (signal.metadata?.processName) {
      targets.push({
        type: 'process',
        name: signal.metadata.processName,
        identifier: signal.metadata.pid?.toString()
      });
    }
    
    return targets;
  }
  
  private buildContext(deviceInfo: any): SignatureContext {
    const uptime = os.uptime();
    let uptime_bucket = '>7d';
    if (uptime < 3600) uptime_bucket = '<1h';
    else if (uptime < 86400) uptime_bucket = '1-24h';
    else if (uptime < 604800) uptime_bucket = '1-7d';
    
    return {
      os_build: `${os.platform()} ${os.release()}`,
      os_version: os.version?.() || os.release(),
      uptime_bucket,
      device_role: deviceInfo.role || 'workstation'
    };
  }
  
  private calculateConfidence(event: EventLogEntry, targets: Target[]): number {
    let confidence = 50;
    
    if ([7034, 7031, 1000, 1001].includes(event.id)) {
      confidence += 30;
    }
    
    if (targets.length > 0) {
      confidence += 10;
    }
    
    if (event.level === 'Error') {
      confidence += 10;
    }
    
    return Math.min(confidence, 100);
  }
  
  private calculateSignalConfidence(signal: SystemSignal): number {
    const value = signal.value;
    const threshold = signal.threshold;

    // Non-numeric or missing/zero threshold — use severity-based confidence
    if (typeof value !== 'number' || typeof threshold !== 'number' || threshold === 0) {
      return signal.severity === 'critical' ? 90 : 75;
    }

    // Inverted metrics (lower = worse): disk_free
    if (signal.metric === 'disk_free') {
      const breach = (threshold - value) / threshold;
      if (breach >= 0.5) return 95;  // e.g., 5% free when threshold is 10%
      if (breach >= 0.2) return 85;  // e.g., 8% free when threshold is 10%
      return 70;
    }

    // Bounded metrics (0-100%): cpu_usage, memory_usage
    if (signal.metric === 'cpu_usage' || signal.metric === 'memory_usage') {
      const headroom = 100 - threshold;
      if (headroom <= 0) return 90; // threshold at or above 100% — always high confidence
      const breach = (value - threshold) / headroom;
      if (breach >= 0.5) return 95;  // e.g., CPU 95% with threshold 90% → 50% of headroom
      if (breach >= 0.2) return 85;  // e.g., CPU 92% with threshold 90% → 20% of headroom
      return 70;
    }

    // Unbounded metrics (process count, error count, MB, ms, etc.): use ratio
    if (value >= threshold * 1.5) return 95;
    if (value >= threshold * 1.2) return 85;
    return 70;
  }
  
  private mapEventLevelToSeverity(level: string): 'low' | 'medium' | 'high' | 'critical' {
    const mapping: Record<string, 'low' | 'medium' | 'high' | 'critical'> = {
      'Critical': 'critical',
      'Error': 'high',
      'Warning': 'medium',
      'Information': 'low'
    };
    return mapping[level] || 'medium';
  }
  
  /**
   * NEW: Map SystemSignal severity ('critical' | 'warning' | 'info') 
   * to Symptom severity ('low' | 'medium' | 'high' | 'critical')
   */
  private mapSystemSignalSeverity(severity: 'critical' | 'warning' | 'info'): 'low' | 'medium' | 'high' | 'critical' {
    const mapping: Record<'critical' | 'warning' | 'info', 'low' | 'medium' | 'high' | 'critical'> = {
      'critical': 'critical',
      'warning': 'medium',
      'info': 'low'
    };
    return mapping[severity];
  }
  
  private mapSignalCategory(category: string): Symptom['type'] {
    const mapping: Record<string, Symptom['type']> = {
      'performance': 'performance',
      'services': 'service_status',
      'disk': 'disk',
      'network': 'network',
      'processes': 'process'
    };
    return mapping[category] || 'performance';
  }
  
  private calculateOverallSeverity(symptoms: Symptom[]): 'low' | 'medium' | 'high' | 'critical' {
    const severities = symptoms.map(s => s.severity);
    if (severities.includes('critical')) return 'critical';
    if (severities.includes('high')) return 'high';
    if (severities.includes('medium')) return 'medium';
    return 'low';
  }
}
