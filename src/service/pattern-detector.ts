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

export interface CrossSignalCorrelation {
  correlationId: string;
  signals: string[];
  category: string;
  confidence: number;
  description: string;
  estimatedFailureDate?: string;
  recommendedAction: string;
  detectedAt: string;
}

export interface ComponentHealthScore {
  component: string;
  score: number; // 0-100 (100 = healthy)
  trend: 'improving' | 'stable' | 'degrading';
  factors: Array<{ signal: string; weight: number; impact: number }>;
  lastUpdated: string;
}

export interface PatternDetectorData {
  occurrences: PatternOccurrence[];
  detectedPatterns: Record<string, DetectedPattern>;
  proactiveActions: Record<string, ProactiveAction>;
  healthScores: Record<string, ComponentHealthScore>;
  correlations: Record<string, CrossSignalCorrelation>;
  degradationHistory: Record<string, Array<{ timestamp: string; score: number }>>;
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
    },
    'smart-errors': {
      threshold: 2,
      recommendation: 'Disk reporting SMART read/write errors. Disk replacement likely needed.',
      urgency: 'immediate',
      proactiveAction: 'Schedule disk replacement - SMART errors indicate hardware degradation'
    },
    'smart-wear': {
      threshold: 2,
      recommendation: 'SSD wear level is high. Drive nearing end of life.',
      urgency: 'high',
      proactiveAction: 'Plan SSD replacement before failure'
    },
    'smart-health': {
      threshold: 1,
      recommendation: 'Disk health status is not Healthy. Immediate attention required.',
      urgency: 'immediate',
      proactiveAction: 'Immediate disk replacement - health status degraded'
    },
    'smart-temp': {
      threshold: 3,
      recommendation: 'Disk running hot repeatedly. Check cooling and airflow.',
      urgency: 'high',
      proactiveAction: 'Investigate disk cooling - overheating can accelerate failure'
    },
    'disk-io': {
      threshold: 10,
      recommendation: 'Disk has been performing slowly across many monitoring cycles. Investigation required.',
      urgency: 'high',
      proactiveAction: 'Disk performance degradation detected - may need replacement or optimization'
    },
    'cpu-temp': {
      threshold: 5,
      recommendation: 'CPU overheating repeatedly. Check cooling system, thermal paste, and airflow.',
      urgency: 'high',
      proactiveAction: 'Cooling system maintenance required'
    },
    'memory-ecc': {
      threshold: 2,
      recommendation: 'Hardware memory errors detected (WHEA). RAM module likely failing.',
      urgency: 'immediate',
      proactiveAction: 'Schedule RAM replacement - hardware memory errors detected'
    },
    'bsod-detected': {
      threshold: 2,
      recommendation: 'Multiple Blue Screen crashes detected. System instability requires investigation.',
      urgency: 'immediate',
      proactiveAction: 'System stability investigation - multiple BSODs indicate hardware or driver failure'
    }
  };

  // Cross-signal correlation rules
  private readonly CORRELATION_RULES: Array<{
    id: string;
    name: string;
    requiredSignals: string[];
    timeWindowMinutes: number;
    confidence: number;
    description: string;
    urgency: 'immediate' | 'high' | 'medium';
    action: string;
  }> = [
    {
      id: 'disk-failure-imminent',
      name: 'Disk Failure Imminent',
      requiredSignals: ['smart-errors', 'disk-io-latency', 'disk-critical'],
      timeWindowMinutes: 1440,
      confidence: 95,
      description: 'SMART errors combined with high disk latency and low disk space indicate imminent disk failure',
      urgency: 'immediate',
      action: 'URGENT: Back up all data immediately and replace disk'
    },
    {
      id: 'disk-degrading',
      name: 'Disk Performance Degradation',
      requiredSignals: ['smart-wear', 'disk-io-latency'],
      timeWindowMinutes: 4320,
      confidence: 80,
      description: 'SSD wear combined with increasing latency indicates disk nearing end of life',
      urgency: 'high',
      action: 'Plan disk replacement within 30 days'
    },
    {
      id: 'memory-hardware-failure',
      name: 'Memory Hardware Failure',
      requiredSignals: ['memory-ecc-error', 'memory-critical'],
      timeWindowMinutes: 1440,
      confidence: 90,
      description: 'Hardware memory errors combined with high memory pressure indicate RAM failure',
      urgency: 'immediate',
      action: 'Replace faulty RAM module'
    },
    {
      id: 'thermal-throttling',
      name: 'Thermal Throttling Detected',
      requiredSignals: ['cpu-temp', 'cpu-critical'],
      timeWindowMinutes: 60,
      confidence: 85,
      description: 'High CPU temperature combined with high CPU usage indicates thermal throttling',
      urgency: 'high',
      action: 'Clean fans, replace thermal paste, improve airflow'
    },
    {
      id: 'system-instability',
      name: 'System Hardware Instability',
      requiredSignals: ['bsod-detected', 'memory-ecc-error'],
      timeWindowMinutes: 4320,
      confidence: 90,
      description: 'BSODs combined with memory errors indicate fundamental hardware instability',
      urgency: 'immediate',
      action: 'Full hardware diagnostic required - replace failing components'
    }
  ];

  // Health score deductions per signal type
  private readonly HEALTH_DEDUCTIONS: Record<string, number> = {
    'smart-errors': 30,
    'smart-wear': 25,
    'smart-health': 40,
    'smart-temp': 10,
    'smart-hours': 5,
    'disk-io-latency': 15,
    'disk-critical': 10,
    'memory-ecc-error': 40,
    'cpu-temp-critical': 30,
    'cpu-temp-high': 15,
    'bsod-detected': 25
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
        const parsed = JSON.parse(data);
        // Migrate v1.0 data to v2.0 by adding missing fields
        if (!parsed.healthScores) parsed.healthScores = {};
        if (!parsed.correlations) parsed.correlations = {};
        if (!parsed.degradationHistory) parsed.degradationHistory = {};
        if (!parsed.version) parsed.version = '2.0';
        return parsed;
      }
    } catch (error) {
      this.logger.error('Failed to load pattern data', error);
    }
    
    return {
      occurrences: [],
      detectedPatterns: {},
      proactiveActions: {},
      healthScores: {},
      correlations: {},
      degradationHistory: {},
      version: '2.0'
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
    this.checkCorrelations(deviceId);
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
    if (signalId.startsWith('smart-errors') || signalId.startsWith('smart-health')) {
      return ['Back up all data immediately', 'Run full disk diagnostic', 'Order replacement disk', 'Schedule replacement during maintenance window'];
    } else if (signalId.startsWith('smart-wear')) {
      return ['Monitor wear level weekly', 'Plan SSD replacement', 'Back up critical data', 'Order replacement drive'];
    } else if (signalId.startsWith('smart-temp') || signalId.startsWith('disk-io')) {
      return ['Check disk cooling and airflow', 'Run disk performance benchmark', 'Consider disk replacement if degradation continues'];
    } else if (signalId.startsWith('cpu-temp')) {
      return ['Clean CPU fan and heatsink', 'Replace thermal paste', 'Check case airflow', 'Consider additional cooling'];
    } else if (signalId.startsWith('memory-ecc')) {
      return ['Run Windows Memory Diagnostic', 'Identify failing RAM module', 'Order replacement RAM', 'Schedule replacement'];
    } else if (signalId.startsWith('bsod')) {
      return ['Analyze crash dump files', 'Check for driver updates', 'Run hardware diagnostics', 'Check memory and disk health'];
    } else if (signalId.includes('disk')) {
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
  
  // ============================================
  // CROSS-SIGNAL CORRELATION ENGINE
  // ============================================

  private checkCorrelations(deviceId: string): void {
    for (const rule of this.CORRELATION_RULES) {
      // Check if this correlation already exists
      const existingCorrelation = Object.values(this.data.correlations).find(
        c => c.category === rule.id && c.signals.some(s => this.data.occurrences.some(o => o.deviceId === deviceId && o.signalId.startsWith(s)))
      );

      if (existingCorrelation) continue;

      const cutoff = new Date();
      cutoff.setMinutes(cutoff.getMinutes() - rule.timeWindowMinutes);

      const recentOccurrences = this.data.occurrences.filter(
        o => o.deviceId === deviceId && new Date(o.timestamp) > cutoff
      );

      // Check if all required signal prefixes have at least one match
      const matchedSignals: string[] = [];
      let allMatched = true;

      for (const requiredPrefix of rule.requiredSignals) {
        const match = recentOccurrences.find(o => o.signalId.startsWith(requiredPrefix));
        if (match) {
          matchedSignals.push(match.signalId);
        } else {
          allMatched = false;
          break;
        }
      }

      if (allMatched) {
        const correlationId = `corr-${rule.id}-${Date.now()}`;
        const componentKey = this.getComponentFromSignals(matchedSignals);
        const failureDate = this.estimateFailureDate(componentKey);

        this.data.correlations[correlationId] = {
          correlationId,
          signals: matchedSignals,
          category: rule.id,
          confidence: rule.confidence,
          description: rule.description,
          estimatedFailureDate: failureDate,
          recommendedAction: rule.action,
          detectedAt: new Date().toISOString()
        };

        this.logger.warn('Cross-signal correlation detected', {
          correlationId,
          category: rule.id,
          confidence: rule.confidence,
          signals: matchedSignals,
          estimatedFailureDate: failureDate
        });

        // Create a proactive action for this correlation
        const actionId = `action-corr-${Date.now()}`;
        this.data.proactiveActions[actionId] = {
          actionId,
          patternId: `correlation:${rule.id}`,
          title: `HARDWARE ALERT: ${rule.name}`,
          description: `${rule.description}. Correlated signals: ${matchedSignals.join(', ')}${failureDate ? `. Estimated failure: ${new Date(failureDate).toLocaleDateString()}` : ''}`,
          reasoning: `Cross-signal correlation with ${rule.confidence}% confidence. ${rule.action}`,
          urgency: rule.urgency,
          steps: [rule.action, 'Back up critical data', 'Order replacement hardware', 'Schedule maintenance window'],
          preventedIssues: ['Hardware failure', 'Data loss', 'Extended downtime', 'Emergency replacement costs'],
          createdAt: new Date().toISOString(),
          status: 'pending'
        };
      }
    }
  }

  private getComponentFromSignals(signals: string[]): string {
    if (signals.some(s => s.startsWith('smart-') || s.startsWith('disk-'))) return 'disk:0';
    if (signals.some(s => s.startsWith('memory-'))) return 'memory';
    if (signals.some(s => s.startsWith('cpu-'))) return 'cpu';
    return 'system';
  }

  // ============================================
  // HARDWARE HEALTH SCORING
  // ============================================

  public updateHealthScore(signalId: string, componentKey: string, severity: string): void {
    // Ensure data structures exist (backward compat with v1.0 data files)
    if (!this.data.healthScores) this.data.healthScores = {};
    if (!this.data.degradationHistory) this.data.degradationHistory = {};

    const existing = this.data.healthScores[componentKey] || {
      component: componentKey,
      score: 100,
      trend: 'stable' as const,
      factors: [],
      lastUpdated: ''
    };

    // Find deduction by matching signal prefix
    let deduction = 0;
    for (const [prefix, value] of Object.entries(this.HEALTH_DEDUCTIONS)) {
      if (signalId.startsWith(prefix)) {
        deduction = value;
        break;
      }
    }

    // Severity multiplier
    if (severity === 'critical') deduction = Math.round(deduction * 1.5);
    if (severity === 'info') deduction = Math.round(deduction * 0.3);

    if (deduction > 0) {
      existing.score = Math.max(0, existing.score - deduction);
      existing.factors.push({
        signal: signalId,
        weight: deduction,
        impact: -deduction
      });

      // Keep only last 50 factors
      if (existing.factors.length > 50) {
        existing.factors = existing.factors.slice(-50);
      }
    }

    existing.lastUpdated = new Date().toISOString();

    // Record in degradation history
    if (!this.data.degradationHistory[componentKey]) {
      this.data.degradationHistory[componentKey] = [];
    }
    this.data.degradationHistory[componentKey].push({
      timestamp: new Date().toISOString(),
      score: existing.score
    });

    // Keep last 500 history entries per component
    if (this.data.degradationHistory[componentKey].length > 500) {
      this.data.degradationHistory[componentKey] = this.data.degradationHistory[componentKey].slice(-500);
    }

    // Calculate trend
    existing.trend = this.calculateTrend(componentKey);

    this.data.healthScores[componentKey] = existing;

    this.logger.info('Health score updated', {
      component: componentKey,
      score: existing.score,
      trend: existing.trend,
      deduction,
      signal: signalId
    });

    // If score drops below 50, estimate failure date
    if (existing.score < 50) {
      const failureDate = this.estimateFailureDate(componentKey);
      if (failureDate) {
        this.logger.warn('Component failure date estimated', {
          component: componentKey,
          score: existing.score,
          estimatedFailure: failureDate
        });
      }
    }

    this.saveData();
  }

  private calculateTrend(componentKey: string): 'improving' | 'stable' | 'degrading' {
    const history = this.data.degradationHistory?.[componentKey];
    if (!history || history.length < 5) return 'stable';

    // Compare average of last 5 scores to average of 5 before that
    const recent = history.slice(-5);
    const older = history.slice(-10, -5);

    if (older.length < 3) return 'stable';

    const recentAvg = recent.reduce((sum, h) => sum + h.score, 0) / recent.length;
    const olderAvg = older.reduce((sum, h) => sum + h.score, 0) / older.length;

    const diff = recentAvg - olderAvg;
    if (diff < -5) return 'degrading';
    if (diff > 5) return 'improving';
    return 'stable';
  }

  // ============================================
  // FAILURE DATE ESTIMATION
  // ============================================

  private estimateFailureDate(componentKey: string): string | undefined {
    const history = this.data.degradationHistory?.[componentKey];
    if (!history || history.length < 5) return undefined;

    // Use last 30 data points for linear regression
    const points = history.slice(-30);
    const n = points.length;
    const t0 = new Date(points[0].timestamp).getTime();

    let sumX = 0, sumY = 0, sumXY = 0, sumXX = 0;
    for (const p of points) {
      const x = (new Date(p.timestamp).getTime() - t0) / (1000 * 60 * 60 * 24); // days
      const y = p.score;
      sumX += x;
      sumY += y;
      sumXY += x * y;
      sumXX += x * x;
    }

    const denominator = n * sumXX - sumX * sumX;
    if (denominator === 0) return undefined;

    const slope = (n * sumXY - sumX * sumY) / denominator;

    // Only estimate if degrading (negative slope)
    if (slope >= 0) return undefined;

    const currentScore = points[points.length - 1].score;
    const failureThreshold = 20; // Score of 20 = component failure
    const daysToFailure = -(currentScore - failureThreshold) / slope;

    if (daysToFailure <= 0 || daysToFailure > 365) return undefined;

    const failureDate = new Date();
    failureDate.setDate(failureDate.getDate() + Math.ceil(daysToFailure));
    return failureDate.toISOString();
  }

  // ============================================
  // PUBLIC API
  // ============================================

  public getHealthScores(): Record<string, ComponentHealthScore> {
    return this.data.healthScores || {};
  }

  public getCorrelations(): Record<string, CrossSignalCorrelation> {
    return this.data.correlations || {};
  }

  public getDetectedPatterns(): DetectedPattern[] {
    return Object.values(this.data.detectedPatterns || {});
  }

  public exportData(): PatternDetectorData {
    return JSON.parse(JSON.stringify(this.data));
  }
}
