// src/service/remediation-memory.ts - Track remediation outcomes and learn from them

import * as fs from 'fs';
import * as path from 'path';
import { Logger } from '../common/logger';

export interface RemediationAttempt {
  timestamp: string;
  playbookId: string;
  signalId: string;
  deviceId: string;
  result: 'success' | 'failure';
  duration: number; // milliseconds
  errorMessage?: string;
}

export interface PlaybookStats {
  playbookId: string;
  totalAttempts: number;
  successCount: number;
  failureCount: number;
  successRate: number;
  lastAttempt: string;
  averageDuration: number;
  recentFailures: number; // Consecutive failures in last 5 attempts
}

export interface SignalStats {
  signalId: string;
  deviceId: string;
  totalAttempts: number;
  successCount: number;
  failureCount: number;
  successRate: number;
  consecutiveFailures: number;
  lastAttempt: string;
  dampened: boolean; // If true, stop auto-remediation
}

export interface DeviceSensitivity {
  deviceId: string;
  totalAttempts: number;
  successCount: number;
  overallSuccessRate: number;
  problemCategories: string[]; // Categories with repeated failures
  sensitiveSignals: string[]; // Signals to avoid on this device
}

export interface ResourceStats {
  resourceId: string;       // e.g. "service-stopped:Spooler"
  totalAttempts: number;
  successCount: number;
  failureCount: number;
  successRate: number;
  consecutiveFailures: number;
  confidenceModifier: number; // 0.0-1.0 multiplier
  lastAttempt: string;
}

export interface RemediationMemoryData {
  attempts: RemediationAttempt[];
  playbookStats: Record<string, PlaybookStats>;
  signalStats: Record<string, SignalStats>;
  deviceSensitivity: Record<string, DeviceSensitivity>;
  resourceStats: Record<string, ResourceStats>;
  version: string;
}

export class RemediationMemory {
  private logger: Logger;
  private filePath: string;
  private memory: RemediationMemoryData;
  
  // Thresholds
  private readonly DAMPENING_THRESHOLD = 5; // Consecutive failures before dampening
  private readonly MIN_ATTEMPTS_FOR_DAMPENING = 5; // Need at least 5 attempts
  private readonly SUCCESS_RATE_THRESHOLD = 0.3; // Below 30% success = problematic
  private readonly MAX_HISTORY_DAYS = 90; // Keep history for 90 days
  
  constructor(logger: Logger, dataDir: string) {
    this.logger = logger;
    this.filePath = path.join(dataDir, 'remediation-memory.json');
    this.memory = this.loadMemory();
  }
  
  /**
   * Load memory from disk or create new
   */
  private loadMemory(): RemediationMemoryData {
    try {
      if (fs.existsSync(this.filePath)) {
        const data = fs.readFileSync(this.filePath, 'utf8');
        const memory = JSON.parse(data) as RemediationMemoryData;
        // Ensure all required fields exist (older files may be missing them)
        memory.signalStats = memory.signalStats || {};
        memory.deviceSensitivity = memory.deviceSensitivity || {};
        memory.attempts = memory.attempts || [];
        memory.playbookStats = memory.playbookStats || {};
        memory.resourceStats = memory.resourceStats || {};
        this.logger.info('Remediation memory loaded', {
          attempts: memory.attempts.length,
          playbooks: Object.keys(memory.playbookStats).length
        });
        return memory;
      }
    } catch (error) {
      this.logger.error('Failed to load remediation memory', error);
    }
    
    // Create new memory
    return {
      attempts: [],
      playbookStats: {},
      signalStats: {},
      deviceSensitivity: {},
      resourceStats: {},
      version: '1.1'
    };
  }
  
  /**
   * Save memory to disk
   */
  private saveMemory(): void {
    try {
      // Clean old attempts before saving
      this.cleanOldAttempts();
      
      fs.writeFileSync(
        this.filePath,
        JSON.stringify(this.memory, null, 2),
        'utf8'
      );
      this.logger.debug('Remediation memory saved');
    } catch (error) {
      this.logger.error('Failed to save remediation memory', error);
    }
  }
  
  /**
   * Record a remediation attempt
   */
  public recordAttempt(
    playbookId: string,
    signalId: string,
    deviceId: string,
    result: 'success' | 'failure',
    duration: number,
    errorMessage?: string,
    resourceName?: string
  ): void {
    const attempt: RemediationAttempt = {
      timestamp: new Date().toISOString(),
      playbookId,
      signalId,
      deviceId,
      result,
      duration,
      errorMessage
    };

    // Add to history
    this.memory.attempts.push(attempt);

    // Update stats
    this.updatePlaybookStats(playbookId, result, duration);
    const safeSignalId = signalId || playbookId || 'unknown';
    this.updateSignalStats(safeSignalId, deviceId, result);
    this.updateDeviceSensitivity(deviceId, safeSignalId, result);

    // Update per-resource stats
    if (resourceName) {
      this.updateResourceStats(safeSignalId, resourceName, result);
    }

    // Save to disk
    this.saveMemory();

    this.logger.info('Remediation attempt recorded', {
      playbookId,
      signalId,
      deviceId,
      result,
      resourceName
    });
  }
  
  /**
   * Update playbook statistics
   */
  private updatePlaybookStats(
    playbookId: string,
    result: 'success' | 'failure',
    duration: number
  ): void {
    let stats = this.memory.playbookStats[playbookId];
    
    if (!stats) {
      stats = {
        playbookId,
        totalAttempts: 0,
        successCount: 0,
        failureCount: 0,
        successRate: 0,
        lastAttempt: new Date().toISOString(),
        averageDuration: 0,
        recentFailures: 0
      };
    }
    
    // Update counts
    stats.totalAttempts++;
    if (result === 'success') {
      stats.successCount++;
      stats.recentFailures = 0; // Reset consecutive failures
    } else {
      stats.failureCount++;
      stats.recentFailures++;
    }
    
    // Calculate success rate
    stats.successRate = stats.successCount / stats.totalAttempts;
    
    // Update average duration
    stats.averageDuration = (stats.averageDuration * (stats.totalAttempts - 1) + duration) / stats.totalAttempts;
    
    stats.lastAttempt = new Date().toISOString();
    
    this.memory.playbookStats[playbookId] = stats;
  }
  
  /**
   * Update signal statistics (per device)
   */
  private updateSignalStats(
    signalId: string,
    deviceId: string,
    result: 'success' | 'failure'
  ): void {
    const key = `${deviceId}:${signalId}`;
    let stats = this.memory.signalStats[key];
    
    if (!stats) {
      stats = {
        signalId,
        deviceId,
        totalAttempts: 0,
        successCount: 0,
        failureCount: 0,
        successRate: 0,
        consecutiveFailures: 0,
        lastAttempt: new Date().toISOString(),
        dampened: false
      };
    }
    
    // Update counts
    stats.totalAttempts++;
    if (result === 'success') {
      stats.successCount++;
      stats.consecutiveFailures = 0; // Reset
    } else {
      stats.failureCount++;
      stats.consecutiveFailures++;
    }
    
    // Calculate success rate
    stats.successRate = stats.successCount / stats.totalAttempts;
    
    stats.lastAttempt = new Date().toISOString();
    
    // Apply dampening if needed
    if (
      stats.totalAttempts >= this.MIN_ATTEMPTS_FOR_DAMPENING &&
      stats.consecutiveFailures >= this.DAMPENING_THRESHOLD
    ) {
      stats.dampened = true;
      this.logger.warn('Signal dampened due to repeated failures', {
        signalId,
        deviceId,
        consecutiveFailures: stats.consecutiveFailures
      });
    }
    
    this.memory.signalStats[key] = stats;
  }
  
  /**
   * Update device sensitivity profile
   */
  private updateDeviceSensitivity(
    deviceId: string,
    signalId: string,
    result: 'success' | 'failure'
  ): void {
    let sensitivity = this.memory.deviceSensitivity[deviceId];
    
    if (!sensitivity) {
      sensitivity = {
        deviceId,
        totalAttempts: 0,
        successCount: 0,
        overallSuccessRate: 0,
        problemCategories: [],
        sensitiveSignals: []
      };
    }
    
    // Update counts
    sensitivity.totalAttempts++;
    if (result === 'success') {
      sensitivity.successCount++;
    }
    
    // Calculate overall success rate
    sensitivity.overallSuccessRate = sensitivity.successCount / sensitivity.totalAttempts;
    
    // Track problematic signals
    const signalKey = `${deviceId}:${signalId}`;
    const signalStats = this.memory.signalStats[signalKey];
    
    if (signalStats && signalStats.dampened) {
      if (!sensitivity.sensitiveSignals.includes(signalId)) {
        sensitivity.sensitiveSignals.push(signalId);
      }
      
      // Extract category from signal ID (e.g., "service-stopped-wuauserv" → "service")
      const category = signalId ? signalId.split('-')[0] : 'unknown';
      if (!sensitivity.problemCategories.includes(category)) {
        sensitivity.problemCategories.push(category);
      }
    }
    
    this.memory.deviceSensitivity[deviceId] = sensitivity;
  }
  
  /**
   * Update per-resource statistics and compute graduated confidence modifier.
   * A playbook may work 90% overall but fail consistently for one specific resource (e.g. Spooler).
   */
  private updateResourceStats(
    signalId: string,
    resourceName: string,
    result: 'success' | 'failure'
  ): void {
    const resourceId = `${signalId}:${resourceName}`;
    let stats = this.memory.resourceStats[resourceId];

    if (!stats) {
      stats = {
        resourceId,
        totalAttempts: 0,
        successCount: 0,
        failureCount: 0,
        successRate: 1,
        consecutiveFailures: 0,
        confidenceModifier: 1.0,
        lastAttempt: new Date().toISOString()
      };
    }

    stats.totalAttempts++;
    if (result === 'success') {
      stats.successCount++;
      stats.consecutiveFailures = 0;
    } else {
      stats.failureCount++;
      stats.consecutiveFailures++;
    }

    stats.successRate = stats.successCount / stats.totalAttempts;
    stats.lastAttempt = new Date().toISOString();

    // Calculate graduated confidence modifier once we have enough data
    if (stats.totalAttempts >= 5) {
      const rate = stats.successRate;
      if (rate >= 1.0) stats.confidenceModifier = 1.0;
      else if (rate >= 0.8) stats.confidenceModifier = 0.9;
      else if (rate >= 0.6) stats.confidenceModifier = 0.7;
      else if (rate >= 0.4) stats.confidenceModifier = 0.5;
      else if (rate >= 0.2) stats.confidenceModifier = 0.3;
      else stats.confidenceModifier = 0.1;
    }

    this.memory.resourceStats[resourceId] = stats;
  }

  /**
   * Check if remediation should be attempted for a signal
   */
  public shouldAttemptRemediation(
    signalId: string,
    deviceId: string,
    playbookId: string,
    resourceName?: string
  ): { allowed: boolean; reason?: string; confidenceModifier: number } {
    let confidenceModifier = 1.0;

    // Check resource-specific stats first (most granular)
    if (resourceName) {
      const resourceId = `${signalId}:${resourceName}`;
      const rStats = this.memory.resourceStats[resourceId];
      if (rStats) {
        if (rStats.consecutiveFailures >= this.DAMPENING_THRESHOLD) {
          return {
            allowed: false,
            reason: `Resource "${resourceName}" dampened after ${rStats.consecutiveFailures} consecutive failures`,
            confidenceModifier: rStats.confidenceModifier
          };
        }
        confidenceModifier = rStats.confidenceModifier;
      }
    }

    // Check signal dampening
    const signalKey = `${deviceId}:${signalId}`;
    const signalStats = this.memory.signalStats[signalKey];

    if (signalStats && signalStats.dampened) {
      return {
        allowed: false,
        reason: `Signal dampened after ${signalStats.consecutiveFailures} consecutive failures`,
        confidenceModifier
      };
    }

    // Check playbook success rate
    const playbookStats = this.memory.playbookStats[playbookId];
    if (
      playbookStats &&
      playbookStats.totalAttempts >= this.MIN_ATTEMPTS_FOR_DAMPENING &&
      playbookStats.successRate < this.SUCCESS_RATE_THRESHOLD
    ) {
      return {
        allowed: false,
        reason: `Playbook has low success rate: ${(playbookStats.successRate * 100).toFixed(1)}%`,
        confidenceModifier
      };
    }

    // Check device sensitivity
    const deviceSensitivity = this.memory.deviceSensitivity[deviceId];
    if (deviceSensitivity && deviceSensitivity.sensitiveSignals.includes(signalId)) {
      return {
        allowed: false,
        reason: `Device has history of failures for this signal type`,
        confidenceModifier
      };
    }

    return { allowed: true, confidenceModifier };
  }
  
  /**
   * Find a cached successful playbook for a given signal+device combo.
   * Returns the playbook ID if one exists with a good success rate, null otherwise.
   */
  public findCachedSolution(signalId: string, deviceId: string): string | null {
    const key = `${deviceId}:${signalId}`;
    const signalStats = this.memory.signalStats[key];

    if (!signalStats || signalStats.dampened || signalStats.totalAttempts === 0) {
      return null;
    }

    // Need at least 1 prior success and a success rate above 70%
    if (signalStats.successCount === 0 || signalStats.successRate < 0.7) {
      return null;
    }

    // Find the most recent successful attempt for this signal+device
    const successfulAttempt = this.memory.attempts
      .filter(a => a.signalId === signalId && a.deviceId === deviceId && a.result === 'success')
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())[0];

    if (successfulAttempt) {
      // Verify the playbook itself still has a decent success rate
      const playbookStats = this.memory.playbookStats[successfulAttempt.playbookId];
      if (playbookStats && playbookStats.successRate >= 0.5) {
        return successfulAttempt.playbookId;
      }
    }

    return null;
  }

  /**
   * Get playbook statistics
   */
  public getPlaybookStats(playbookId: string): PlaybookStats | null {
    return this.memory.playbookStats[playbookId] || null;
  }
  
  /**
   * Get signal statistics
   */
  public getSignalStats(signalId: string, deviceId: string): SignalStats | null {
    const key = `${deviceId}:${signalId}`;
    return this.memory.signalStats[key] || null;
  }
  
  /**
   * Get device sensitivity profile
   */
  public getDeviceSensitivity(deviceId: string): DeviceSensitivity | null {
    return this.memory.deviceSensitivity[deviceId] || null;
  }
  
  /**
   * Get resource-specific stats
   */
  public getResourceStats(signalId: string, resourceName: string): ResourceStats | null {
    const resourceId = `${signalId}:${resourceName}`;
    return this.memory.resourceStats[resourceId] || null;
  }

  /**
   * Reset dampening for a signal (manual override)
   */
  public resetDampening(signalId: string, deviceId: string): void {
    const key = `${deviceId}:${signalId}`;
    const stats = this.memory.signalStats[key];
    
    if (stats) {
      stats.dampened = false;
      stats.consecutiveFailures = 0;
      this.saveMemory();
      this.logger.info('Signal dampening reset', { signalId, deviceId });
    }
  }
  
  /**
   * Get summary statistics
   */
  public getSummary(): {
    totalAttempts: number;
    totalSuccesses: number;
    totalFailures: number;
    overallSuccessRate: number;
    dampenedSignals: number;
    problematicPlaybooks: number;
  } {
    const totalAttempts = this.memory.attempts.length;
    const totalSuccesses = this.memory.attempts.filter(a => a.result === 'success').length;
    const totalFailures = totalAttempts - totalSuccesses;
    const overallSuccessRate = totalAttempts > 0 ? totalSuccesses / totalAttempts : 0;
    
    const dampenedSignals = Object.values(this.memory.signalStats)
      .filter(s => s.dampened).length;
    
    const problematicPlaybooks = Object.values(this.memory.playbookStats)
      .filter(p => 
        p.totalAttempts >= this.MIN_ATTEMPTS_FOR_DAMPENING &&
        p.successRate < this.SUCCESS_RATE_THRESHOLD
      ).length;
    
    return {
      totalAttempts,
      totalSuccesses,
      totalFailures,
      overallSuccessRate,
      dampenedSignals,
      problematicPlaybooks
    };
  }
  
  /**
   * Clean old attempts (keep last 90 days)
   */
  private cleanOldAttempts(): void {
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - this.MAX_HISTORY_DAYS);
    
    const before = this.memory.attempts.length;
    this.memory.attempts = this.memory.attempts.filter(
      a => new Date(a.timestamp) > cutoff
    );
    
    const removed = before - this.memory.attempts.length;
    if (removed > 0) {
      this.logger.info(`Cleaned ${removed} old remediation attempts`);
    }
  }
  
  /**
   * Get recent failures for a playbook
   */
  public getRecentFailures(playbookId: string, limit: number = 5): RemediationAttempt[] {
    return this.memory.attempts
      .filter(a => a.playbookId === playbookId && a.result === 'failure')
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
      .slice(0, limit);
  }
  
  /**
   * Export memory data for analysis
   */
  public exportData(): RemediationMemoryData {
    return JSON.parse(JSON.stringify(this.memory));
  }
}
