// src/service/pattern-detector.ts - Detect recurring patterns and suggest proactive actions

import * as fs from 'fs';
import * as path from 'path';
import { Logger } from '../common/logger';

export interface PatternOccurrence {
  timestamp: string;
  signalId: string;
  category: string;
  deviceId: string;
  severity: 'critical' | 'warning' | 'info';
  metadata?: Record<string, any>;
}

export interface DetectedPattern {
  patternId: string;
  signalId: string;
  category: string;
  deviceId: string;
  occurrenceCount: number;
  firstOccurrence: string;
  lastOccurrence: string;
  frequency: number; // occurrences per day
  trend: 'increasing' | 'stable' | 'decreasing';
  recommendation: string;
  urgency: 'immediate' | 'high' | 'medium' | 'low';
  estimatedFailureDate?: string;
}

export interface ProactiveAction {
  actionId: string;
  patternId: string;
  title: string;
  description: string;
  reasoning: string;
  urgency: 'immediate' | 'high' | 'medium' | 'low';
  estimatedCost?: string;
  estimatedDowntime?: string;
  steps: string[];
  preventedIssues: string[];
  createdAt: string;
  status: 'pending' | 'acknowledged' | 'scheduled' | 'completed' | 'dismissed';
  aiAnalysis?: string; // AI-generated analysis and recommendations
}

export interface PatternDetectorData {
  occurrences: PatternOccurrence[];
  detectedPatterns: Record<string, DetectedPattern>;
  proactiveActions: Record<string, ProactiveAction>;
  version: string;
}

export class PatternDetector {
  private logger: Logger;
  private filePath: string;
  private data: PatternDetectorData;
  
  // Detection thresholds
  private readonly MIN_OCCURRENCES_FOR_PATTERN = 3;
  private readonly PATTERN_DETECTION_WINDOW_DAYS = 30;
  
  // Pattern rules
  private readonly PATTERN_RULES: Record<string, any> = {
    'disk-critical': {
      threshold: 3,
      recommendation: 'Disk space critically low multiple times. Consider: 1) Add storage, 2) Archive data, 3) Review log files',
      urgency: 'high',
      proactiveAction: 'Upgrade disk or implement automated archival'
    },
    'service-stopped': {
      threshold: 4,
      recommendation: 'Service repeatedly stopping. Investigate: 1) Service stability, 2) Resource constraints, 3) Configuration',
      urgency: 'high',
      proactiveAction: 'Root cause investigation required'
    },
    'memory-critical': {
      threshold: 3,
      recommendation: 'Critical memory pressure. System needs: 1) More RAM, 2) Memory leak investigation, 3) App optimization',
      urgency: 'high',
      proactiveAction: 'RAM upgrade or memory leak fix'
    }
  };
  
  constructor(logger: Logger, dataDir: string) {
    this.logger = logger;
    this.filePath = path.join(dataDir, 'pattern-detector.json');
    this.data = this.loadData();
    
    if (!fs.existsSync(this.filePath)) {
      this.saveData();
      this.logger.info('Pattern detector initialized');
    }
  }
  
  private loadData(): PatternDetectorData {
    try {
      if (fs.existsSync(this.filePath)) {
        const data = fs.readFileSync(this.filePath, 'utf8');
        return JSON.parse(data);
      }
    } catch (error) {
      this.logger.error('Failed to load pattern data', error);
    }
    
    return {
      occurrences: [],
      detectedPatterns: {},
      proactiveActions: {},
      version: '1.0'
    };
  }
  
  private saveData(): void {
    try {
      fs.writeFileSync(this.filePath, JSON.stringify(this.data, null, 2));
    } catch (error) {
      this.logger.error('Failed to save pattern data', error);
    }
  }
  
  public recordOccurrence(
    signalId: string,
    category: string,
    deviceId: string,
    severity: 'critical' | 'warning' | 'info',
    metadata?: Record<string, any>
  ): void {
    this.data.occurrences.push({
      timestamp: new Date().toISOString(),
      signalId,
      category,
      deviceId,
      severity,
      metadata
    });
    
    this.analyzePatterns(signalId, deviceId);
    this.saveData();
  }
  
  private analyzePatterns(signalId: string, deviceId: string): void {
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - this.PATTERN_DETECTION_WINDOW_DAYS);
    
    const relevantOccurrences = this.data.occurrences.filter(
      o => o.signalId === signalId && o.deviceId === deviceId && new Date(o.timestamp) > cutoff
    );
    
    if (relevantOccurrences.length < this.MIN_OCCURRENCES_FOR_PATTERN) {
      return;
    }
    
    const patternKey = this.getPatternKey(signalId);
    const rule = this.PATTERN_RULES[patternKey];
    
    if (!rule || relevantOccurrences.length < rule.threshold) {
      return;
    }
    
    const patternId = `${deviceId}:${signalId}`;
    
    // Check if we already created an action for this pattern
    const existingAction = Object.values(this.data.proactiveActions).find(
      a => a.patternId === patternId && a.status === 'pending'
    );
    
    if (!existingAction) {
      this.createProactiveAction(signalId, deviceId, relevantOccurrences, rule);
    }
  }
  
  private createProactiveAction(
    signalId: string,
    deviceId: string,
    occurrences: PatternOccurrence[],
    rule: any
  ): void {
    const actionId = `action-${Date.now()}`;
    const patternId = `${deviceId}:${signalId}`;
    
    this.data.proactiveActions[actionId] = {
      actionId,
      patternId,
      title: this.generateTitle(signalId, occurrences.length),
      description: `${signalId} has occurred ${occurrences.length} times in the past ${this.PATTERN_DETECTION_WINDOW_DAYS} days. ${rule.recommendation}`,
      reasoning: `Recurring pattern detected. ${rule.proactiveAction}`,
      urgency: rule.urgency,
      steps: this.generateSteps(signalId),
      preventedIssues: this.generatePreventedIssues(signalId),
      createdAt: new Date().toISOString(),
      status: 'pending'
    };
    
    this.logger.warn('Proactive action created', { actionId, signalId });
  }
  
  private generateTitle(signalId: string, count: number): string {
    const category = signalId.split('-')[0];
    return `${category.toUpperCase()} Issue: Action Required (${count} occurrences)`;
  }
  
  private generateSteps(signalId: string): string[] {
    if (signalId.includes('disk')) {
      return ['Review disk usage', 'Archive old data', 'Add storage capacity'];
    } else if (signalId.includes('service')) {
      return ['Check service logs', 'Review dependencies', 'Update service'];
    } else if (signalId.includes('memory')) {
      return ['Identify memory leaks', 'Optimize applications', 'Upgrade RAM'];
    }
    return ['Investigate root cause', 'Implement fix', 'Monitor'];
  }
  
  private generatePreventedIssues(signalId: string): string[] {
    return ['System failure', 'Data loss', 'Service outage', 'Performance degradation'];
  }
  
  private getPatternKey(signalId: string): string {
    const parts = signalId.split('-');
    return parts.length >= 2 ? `${parts[0]}-${parts[1]}` : signalId;
  }
  
  public getPendingActions(): ProactiveAction[] {
    return Object.values(this.data.proactiveActions)
      .filter(a => a.status === 'pending')
      .sort((a, b) => {
        const order = { immediate: 0, high: 1, medium: 2, low: 3 };
        return order[a.urgency] - order[b.urgency];
      });
  }
  
  public exportData(): PatternDetectorData {
    return JSON.parse(JSON.stringify(this.data));
  }
}
