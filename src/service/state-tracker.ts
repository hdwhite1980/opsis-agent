// state-tracker.ts - Resource state tracking, deduplication, severity escalation, flap detection, dependency awareness
import * as fs from 'fs';
import * as path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';
import { Logger } from '../common/logger';

const execAsync = promisify(exec);

// ============================================
// INTERFACES
// ============================================

export interface ResourceState {
  resourceId: string;
  resourceType: 'service' | 'process' | 'metric' | 'disk' | 'network';
  currentState: string;
  previousState: string | null;
  stateChangedAt: string;
  lastCheckedAt: string;
  signalCount: number;
  severityLevel: 'info' | 'warning' | 'high' | 'critical';
  escalationCheckpoints: {
    warning?: string;
    high?: string;
    critical?: string;
  };
  transitionHistory: Array<{ timestamp: string; fromState: string; toState: string }>;
  isFlapping: boolean;
  flapDetectedAt?: string;
  metadata?: Record<string, any>;
}

export interface StateChangeEvent {
  resourceId: string;
  resourceType: string;
  fromState: string | null;
  toState: string;
  changedAt: Date;
  isNewState: boolean;
  isFlap?: boolean;
  transitionCount?: number;
}

export interface SeverityEscalationConfig {
  enabled: boolean;
  tiers: {
    warning_to_high_minutes: number;
    high_to_critical_minutes: number;
  };
  categoryOverrides?: Record<string, { warning_to_high_minutes: number; high_to_critical_minutes: number }>;
}

export interface SeverityEscalationEvent {
  resourceId: string;
  escalatedFrom: string;
  escalatedTo: string;
  durationMinutes: number;
  originalSignalTimestamp: string;
}

export interface FlapDetectionConfig {
  enabled: boolean;
  transitionThreshold: number;
  windowMinutes: number;
  stablePeriodMinutes: number;
}

export interface DependencyMap {
  serviceDependencies: Record<string, string[]>;
  serviceDependents: Record<string, string[]>;
  lastRefreshed: string;
}

export interface StateTrackerData {
  resources: Record<string, ResourceState>;
  dependencyMap: DependencyMap;
  version: string;
}

// ============================================
// STATE TRACKER
// ============================================

export class StateTracker {
  private logger: Logger;
  private states: Map<string, ResourceState> = new Map();
  private filePath: string;
  private dependencyMap: DependencyMap = {
    serviceDependencies: {},
    serviceDependents: {},
    lastRefreshed: ''
  };

  private severityConfig: SeverityEscalationConfig = {
    enabled: true,
    tiers: {
      warning_to_high_minutes: 5,
      high_to_critical_minutes: 15
    }
  };

  private flapConfig: FlapDetectionConfig = {
    enabled: true,
    transitionThreshold: 4,
    windowMinutes: 10,
    stablePeriodMinutes: 15
  };

  constructor(logger: Logger, dataDir: string) {
    this.logger = logger;
    this.filePath = path.join(dataDir, 'state-tracker.json');
    this.load();
  }

  // ============================================
  // CORE STATE TRACKING (Feature 2: Deduplication)
  // ============================================

  public checkState(
    resourceId: string,
    resourceType: ResourceState['resourceType'],
    currentState: string,
    severity: ResourceState['severityLevel'] = 'warning',
    metadata?: Record<string, any>
  ): StateChangeEvent | null {
    const existing = this.states.get(resourceId);
    const now = new Date();

    if (!existing) {
      const newState: ResourceState = {
        resourceId,
        resourceType,
        currentState,
        previousState: null,
        stateChangedAt: now.toISOString(),
        lastCheckedAt: now.toISOString(),
        signalCount: 1,
        severityLevel: severity,
        escalationCheckpoints: { [severity]: now.toISOString() },
        transitionHistory: [],
        isFlapping: false,
        metadata
      };
      this.states.set(resourceId, newState);
      this.save();

      return {
        resourceId, resourceType,
        fromState: null, toState: currentState,
        changedAt: now, isNewState: true
      };
    }

    existing.lastCheckedAt = now.toISOString();

    // Same state — deduplicate
    if (existing.currentState === currentState) {
      existing.signalCount++;
      return null;
    }

    // State changed — record transition
    const fromState = existing.currentState;

    existing.transitionHistory.push({
      timestamp: now.toISOString(),
      fromState,
      toState: currentState
    });

    // Flap detection (Feature 4)
    if (this.flapConfig.enabled) {
      const flapResult = this.checkForFlapping(existing);
      if (flapResult) {
        this.save();
        return flapResult;
      }
    }

    // Normal state change
    existing.previousState = fromState;
    existing.currentState = currentState;
    existing.stateChangedAt = now.toISOString();
    existing.signalCount = 1;
    existing.severityLevel = severity;
    existing.escalationCheckpoints = { [severity]: now.toISOString() };
    existing.metadata = metadata;

    this.save();

    return {
      resourceId, resourceType,
      fromState, toState: currentState,
      changedAt: now, isNewState: true
    };
  }

  public getResourceState(resourceId: string): ResourceState | null {
    return this.states.get(resourceId) || null;
  }

  public getAllStates(): ResourceState[] {
    return Array.from(this.states.values());
  }

  public getActiveIssues(): ResourceState[] {
    return this.getAllStates().filter(s =>
      s.currentState !== 'normal' && s.currentState !== 'running' && s.currentState !== 'ok'
    );
  }

  public clearState(resourceId: string): void {
    this.states.delete(resourceId);
    this.save();
  }

  public clearAllStates(): void {
    this.states.clear();
    this.save();
  }

  // ============================================
  // SEVERITY ESCALATION (Feature 3)
  // ============================================

  public updateSeverityConfig(config: SeverityEscalationConfig): void {
    this.severityConfig = config;
    this.logger.info('Severity escalation config updated', { config });
  }

  public checkSeverityEscalation(): SeverityEscalationEvent[] {
    if (!this.severityConfig.enabled) return [];

    const events: SeverityEscalationEvent[] = [];
    const now = Date.now();

    for (const [, state] of this.states) {
      // Only escalate resources in abnormal state
      if (state.currentState === 'normal' || state.currentState === 'running' || state.currentState === 'ok') {
        continue;
      }
      if (state.isFlapping) continue;

      const thresholds = this.getEscalationThresholds(state.resourceType);
      const stateAge = now - new Date(state.stateChangedAt).getTime();
      const stateAgeMinutes = stateAge / 60000;

      if (state.severityLevel === 'warning' && stateAgeMinutes >= thresholds.warning_to_high) {
        state.severityLevel = 'high';
        state.escalationCheckpoints.high = new Date().toISOString();
        events.push({
          resourceId: state.resourceId,
          escalatedFrom: 'warning',
          escalatedTo: 'high',
          durationMinutes: Math.round(stateAgeMinutes),
          originalSignalTimestamp: state.stateChangedAt
        });
      } else if (state.severityLevel === 'high' && stateAgeMinutes >= (thresholds.warning_to_high + thresholds.high_to_critical)) {
        state.severityLevel = 'critical';
        state.escalationCheckpoints.critical = new Date().toISOString();
        events.push({
          resourceId: state.resourceId,
          escalatedFrom: 'high',
          escalatedTo: 'critical',
          durationMinutes: Math.round(stateAgeMinutes),
          originalSignalTimestamp: state.stateChangedAt
        });
      }
    }

    if (events.length > 0) this.save();
    return events;
  }

  private getEscalationThresholds(resourceType: string): { warning_to_high: number; high_to_critical: number } {
    const override = this.severityConfig.categoryOverrides?.[resourceType];
    if (override) {
      return {
        warning_to_high: override.warning_to_high_minutes,
        high_to_critical: override.high_to_critical_minutes
      };
    }
    return {
      warning_to_high: this.severityConfig.tiers.warning_to_high_minutes,
      high_to_critical: this.severityConfig.tiers.high_to_critical_minutes
    };
  }

  // ============================================
  // FLAP DETECTION (Feature 4)
  // ============================================

  public updateFlapConfig(config: FlapDetectionConfig): void {
    this.flapConfig = config;
    this.logger.info('Flap detection config updated', { config });
  }

  public getFlapConfig(): FlapDetectionConfig {
    return { ...this.flapConfig };
  }

  private checkForFlapping(state: ResourceState): StateChangeEvent | null {
    // Trim old transitions outside window
    const windowStart = Date.now() - (this.flapConfig.windowMinutes * 60000);
    state.transitionHistory = state.transitionHistory.filter(
      t => new Date(t.timestamp).getTime() > windowStart
    );

    if (state.transitionHistory.length >= this.flapConfig.transitionThreshold) {
      if (!state.isFlapping) {
        // Entering flap state
        state.isFlapping = true;
        state.flapDetectedAt = new Date().toISOString();

        this.logger.warn('Flap detected', {
          resourceId: state.resourceId,
          transitions: state.transitionHistory.length,
          window: this.flapConfig.windowMinutes
        });

        return {
          resourceId: state.resourceId,
          resourceType: state.resourceType,
          fromState: state.currentState,
          toState: 'flapping',
          changedAt: new Date(),
          isNewState: true,
          isFlap: true,
          transitionCount: state.transitionHistory.length
        };
      }
      // Already flapping — suppress individual state changes
      return null;
    }

    return null;
  }

  public checkFlapStability(): string[] {
    const stableResources: string[] = [];

    for (const [, state] of this.states) {
      if (!state.isFlapping) continue;

      const lastTransition = state.transitionHistory[state.transitionHistory.length - 1];
      if (!lastTransition) {
        state.isFlapping = false;
        stableResources.push(state.resourceId);
        continue;
      }

      const msSinceLastTransition = Date.now() - new Date(lastTransition.timestamp).getTime();
      if (msSinceLastTransition > this.flapConfig.stablePeriodMinutes * 60000) {
        state.isFlapping = false;
        state.transitionHistory = [];

        this.logger.info('Resource stable after flapping', {
          resourceId: state.resourceId,
          stableMinutes: this.flapConfig.stablePeriodMinutes
        });

        stableResources.push(state.resourceId);
      }
    }

    if (stableResources.length > 0) this.save();
    return stableResources;
  }

  public getFlappingResources(): ResourceState[] {
    return this.getAllStates().filter(s => s.isFlapping);
  }

  // ============================================
  // DEPENDENCY AWARENESS (Feature 5)
  // ============================================

  public async refreshDependencyMap(): Promise<void> {
    try {
      const psCommand = `powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-Service | Where-Object { $_.ServicesDependedOn.Count -gt 0 } | ForEach-Object { [PSCustomObject]@{ Name=$_.Name; DependsOn=@($_.ServicesDependedOn.Name) } } | ConvertTo-Json -Depth 3"`;

      const { stdout } = await execAsync(psCommand, { timeout: 30000 });
      if (!stdout.trim()) {
        this.logger.debug('No service dependencies found');
        return;
      }

      const parsed = JSON.parse(stdout.trim());
      const services = Array.isArray(parsed) ? parsed : [parsed];

      const dependencies: Record<string, string[]> = {};
      const dependents: Record<string, string[]> = {};

      for (const svc of services) {
        if (!svc.Name || !svc.DependsOn) continue;

        const deps = Array.isArray(svc.DependsOn) ? svc.DependsOn : [svc.DependsOn];
        dependencies[svc.Name] = deps;

        // Build reverse map
        for (const dep of deps) {
          if (!dependents[dep]) dependents[dep] = [];
          if (!dependents[dep].includes(svc.Name)) {
            dependents[dep].push(svc.Name);
          }
        }
      }

      this.dependencyMap = {
        serviceDependencies: dependencies,
        serviceDependents: dependents,
        lastRefreshed: new Date().toISOString()
      };

      this.logger.info('Dependency map refreshed', {
        services: Object.keys(dependencies).length,
        parentServices: Object.keys(dependents).length
      });

      this.save();
    } catch (error: any) {
      this.logger.warn('Failed to refresh dependency map', { error: error.message });
    }
  }

  public getParentDependencies(serviceName: string): string[] {
    return this.dependencyMap.serviceDependencies[serviceName] || [];
  }

  public getDependentServices(serviceName: string): string[] {
    return this.dependencyMap.serviceDependents[serviceName] || [];
  }

  public isDownstreamOfDownParent(serviceName: string): { isDownstream: boolean; downParents: string[] } {
    const parents = this.getParentDependencies(serviceName);
    if (parents.length === 0) return { isDownstream: false, downParents: [] };

    const downParents: string[] = [];

    for (const parent of parents) {
      const parentState = this.states.get(`service:${parent}`);
      if (parentState && parentState.currentState !== 'running' && parentState.currentState !== 'ok' && parentState.currentState !== 'normal') {
        downParents.push(parent);
      }
    }

    return {
      isDownstream: downParents.length > 0,
      downParents
    };
  }

  public getDependencyMap(): DependencyMap {
    return { ...this.dependencyMap };
  }

  // ============================================
  // SUMMARY
  // ============================================

  public getSummary(): { activeIssues: number; flapping: number; escalatedSeverities: number } {
    let activeIssues = 0;
    let flapping = 0;
    let escalatedSeverities = 0;

    for (const [, state] of this.states) {
      if (state.currentState !== 'normal' && state.currentState !== 'running' && state.currentState !== 'ok') {
        activeIssues++;
      }
      if (state.isFlapping) flapping++;
      if (state.escalationCheckpoints.high || state.escalationCheckpoints.critical) {
        escalatedSeverities++;
      }
    }

    return { activeIssues, flapping, escalatedSeverities };
  }

  // ============================================
  // PERSISTENCE
  // ============================================

  private load(): void {
    try {
      if (fs.existsSync(this.filePath)) {
        const raw = fs.readFileSync(this.filePath, 'utf-8');
        const data: StateTrackerData = JSON.parse(raw);

        for (const [key, value] of Object.entries(data.resources || {})) {
          this.states.set(key, value);
        }

        if (data.dependencyMap) {
          this.dependencyMap = data.dependencyMap;
        }

        this.logger.info('State tracker loaded', {
          resources: this.states.size,
          dependencies: Object.keys(this.dependencyMap.serviceDependencies).length
        });
      }
    } catch (error: any) {
      this.logger.warn('Failed to load state tracker data', { error: error.message });
    }
  }

  private save(): void {
    try {
      const data: StateTrackerData = {
        resources: Object.fromEntries(this.states),
        dependencyMap: this.dependencyMap,
        version: '1.0.0'
      };
      fs.writeFileSync(this.filePath, JSON.stringify(data, null, 2), { mode: 0o600 });
    } catch (error: any) {
      this.logger.warn('Failed to save state tracker data', { error: error.message });
    }
  }
}
