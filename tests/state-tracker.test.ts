import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { StateTracker } from '../src/service/state-tracker';

// Mock logger
const mockLogger: any = {
  info: jest.fn(),
  warn: jest.fn(),
  debug: jest.fn(),
  error: jest.fn(),
};

// Mock child_process.exec to avoid actual PowerShell calls
jest.mock('child_process', () => ({
  exec: jest.fn(),
  spawn: jest.fn(),
  ChildProcess: jest.fn(),
}));
jest.mock('util', () => ({
  ...jest.requireActual('util'),
  promisify: () => jest.fn().mockResolvedValue({ stdout: '[]', stderr: '' }),
}));

let tmpDir: string;
let tracker: StateTracker;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opsis-state-test-'));
  mockLogger.info.mockClear();
  mockLogger.warn.mockClear();
  mockLogger.debug.mockClear();
  tracker = new StateTracker(mockLogger, tmpDir);
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

// ============================================
// CORE STATE TRACKING / DEDUPLICATION
// ============================================

describe('StateTracker - Core State Tracking', () => {
  it('returns a StateChangeEvent on first observation of a resource', () => {
    const result = tracker.checkState('service:W32Time', 'service', 'stopped');
    expect(result).not.toBeNull();
    expect(result!.isNewState).toBe(true);
    expect(result!.fromState).toBeNull();
    expect(result!.toState).toBe('stopped');
    expect(result!.resourceId).toBe('service:W32Time');
  });

  it('returns null (dedup) when same state is reported again', () => {
    tracker.checkState('service:W32Time', 'service', 'stopped');
    const second = tracker.checkState('service:W32Time', 'service', 'stopped');
    expect(second).toBeNull();
  });

  it('increments signalCount on duplicate observations', () => {
    tracker.checkState('service:W32Time', 'service', 'stopped');
    tracker.checkState('service:W32Time', 'service', 'stopped');
    tracker.checkState('service:W32Time', 'service', 'stopped');

    const state = tracker.getResourceState('service:W32Time');
    expect(state).not.toBeNull();
    expect(state!.signalCount).toBe(3);
  });

  it('returns StateChangeEvent on actual state change', () => {
    tracker.checkState('service:W32Time', 'service', 'stopped');
    const change = tracker.checkState('service:W32Time', 'service', 'running');

    expect(change).not.toBeNull();
    expect(change!.fromState).toBe('stopped');
    expect(change!.toState).toBe('running');
    expect(change!.isNewState).toBe(true);
  });

  it('records previousState on state change', () => {
    tracker.checkState('service:W32Time', 'service', 'stopped');
    tracker.checkState('service:W32Time', 'service', 'running');

    const state = tracker.getResourceState('service:W32Time');
    expect(state!.previousState).toBe('stopped');
    expect(state!.currentState).toBe('running');
  });

  it('getActiveIssues filters out normal/running/ok states', () => {
    tracker.checkState('service:A', 'service', 'stopped');
    tracker.checkState('service:B', 'service', 'running');
    tracker.checkState('metric:cpu', 'metric', 'critical');
    tracker.checkState('disk:C', 'disk', 'ok');

    const issues = tracker.getActiveIssues();
    expect(issues).toHaveLength(2);
    expect(issues.map(i => i.resourceId).sort()).toEqual(['metric:cpu', 'service:A']);
  });

  it('clearState removes a specific resource', () => {
    tracker.checkState('service:A', 'service', 'stopped');
    tracker.checkState('service:B', 'service', 'stopped');
    tracker.clearState('service:A');

    expect(tracker.getResourceState('service:A')).toBeNull();
    expect(tracker.getResourceState('service:B')).not.toBeNull();
  });

  it('clearAllStates removes everything', () => {
    tracker.checkState('service:A', 'service', 'stopped');
    tracker.checkState('service:B', 'service', 'stopped');
    tracker.clearAllStates();

    expect(tracker.getAllStates()).toHaveLength(0);
  });
});

// ============================================
// PERSISTENCE
// ============================================

describe('StateTracker - Persistence', () => {
  it('persists state to disk and loads on new instance', () => {
    tracker.checkState('service:W32Time', 'service', 'stopped', 'warning');

    // Create a new tracker from the same directory
    const tracker2 = new StateTracker(mockLogger, tmpDir);
    const state = tracker2.getResourceState('service:W32Time');

    expect(state).not.toBeNull();
    expect(state!.currentState).toBe('stopped');
    expect(state!.severityLevel).toBe('warning');
  });

  it('handles missing persistence file gracefully', () => {
    const emptyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opsis-empty-'));
    const t = new StateTracker(mockLogger, emptyDir);
    expect(t.getAllStates()).toHaveLength(0);
    fs.rmSync(emptyDir, { recursive: true, force: true });
  });
});

// ============================================
// SEVERITY ESCALATION
// ============================================

describe('StateTracker - Severity Escalation', () => {
  it('returns empty array when no escalation needed', () => {
    tracker.checkState('service:W32Time', 'service', 'stopped', 'warning');
    const events = tracker.checkSeverityEscalation();
    expect(events).toHaveLength(0);
  });

  it('escalates warning → high after configured minutes', () => {
    // Set very short threshold for testing
    tracker.updateSeverityConfig({
      enabled: true,
      tiers: { warning_to_high_minutes: 0, high_to_critical_minutes: 0 },
    });

    tracker.checkState('service:W32Time', 'service', 'stopped', 'warning');

    // Manually backdate the stateChangedAt to simulate time passing
    const state = tracker.getResourceState('service:W32Time')!;
    state.stateChangedAt = new Date(Date.now() - 6 * 60000).toISOString();

    const events = tracker.checkSeverityEscalation();
    expect(events).toHaveLength(1);
    expect(events[0].escalatedFrom).toBe('warning');
    expect(events[0].escalatedTo).toBe('high');
    expect(events[0].resourceId).toBe('service:W32Time');
  });

  it('escalates high → critical after combined threshold', () => {
    tracker.updateSeverityConfig({
      enabled: true,
      tiers: { warning_to_high_minutes: 0, high_to_critical_minutes: 0 },
    });

    tracker.checkState('service:W32Time', 'service', 'stopped', 'high');
    const state = tracker.getResourceState('service:W32Time')!;
    state.stateChangedAt = new Date(Date.now() - 20 * 60000).toISOString();

    const events = tracker.checkSeverityEscalation();
    expect(events).toHaveLength(1);
    expect(events[0].escalatedFrom).toBe('high');
    expect(events[0].escalatedTo).toBe('critical');
  });

  it('does not escalate resources in normal state', () => {
    tracker.updateSeverityConfig({
      enabled: true,
      tiers: { warning_to_high_minutes: 0, high_to_critical_minutes: 0 },
    });

    tracker.checkState('service:W32Time', 'service', 'running', 'warning');
    const state = tracker.getResourceState('service:W32Time')!;
    state.stateChangedAt = new Date(Date.now() - 60 * 60000).toISOString();

    const events = tracker.checkSeverityEscalation();
    expect(events).toHaveLength(0);
  });

  it('does not escalate flapping resources', () => {
    tracker.updateSeverityConfig({
      enabled: true,
      tiers: { warning_to_high_minutes: 0, high_to_critical_minutes: 0 },
    });

    tracker.checkState('service:W32Time', 'service', 'stopped', 'warning');
    const state = tracker.getResourceState('service:W32Time')!;
    state.isFlapping = true;
    state.stateChangedAt = new Date(Date.now() - 60 * 60000).toISOString();

    const events = tracker.checkSeverityEscalation();
    expect(events).toHaveLength(0);
  });

  it('returns empty when escalation is disabled', () => {
    tracker.updateSeverityConfig({
      enabled: false,
      tiers: { warning_to_high_minutes: 0, high_to_critical_minutes: 0 },
    });

    tracker.checkState('service:W32Time', 'service', 'stopped', 'warning');
    const state = tracker.getResourceState('service:W32Time')!;
    state.stateChangedAt = new Date(Date.now() - 60 * 60000).toISOString();

    expect(tracker.checkSeverityEscalation()).toHaveLength(0);
  });

  it('respects category overrides for escalation thresholds', () => {
    tracker.updateSeverityConfig({
      enabled: true,
      tiers: { warning_to_high_minutes: 999, high_to_critical_minutes: 999 },
      categoryOverrides: {
        service: { warning_to_high_minutes: 0, high_to_critical_minutes: 0 }
      }
    });

    tracker.checkState('service:W32Time', 'service', 'stopped', 'warning');
    const state = tracker.getResourceState('service:W32Time')!;
    state.stateChangedAt = new Date(Date.now() - 6 * 60000).toISOString();

    const events = tracker.checkSeverityEscalation();
    expect(events).toHaveLength(1);
    expect(events[0].escalatedTo).toBe('high');
  });
});

// ============================================
// FLAP DETECTION
// ============================================

describe('StateTracker - Flap Detection', () => {
  beforeEach(() => {
    tracker.updateFlapConfig({
      enabled: true,
      transitionThreshold: 4,
      windowMinutes: 10,
      stablePeriodMinutes: 1, // 1 min for test speed
    });
  });

  it('does not flag as flapping below threshold', () => {
    tracker.checkState('service:A', 'service', 'stopped');
    const r2 = tracker.checkState('service:A', 'service', 'running');
    const r3 = tracker.checkState('service:A', 'service', 'stopped');

    // 2 transitions, threshold is 4
    expect(r2).not.toBeNull();
    expect(r2!.isFlap).toBeUndefined();
    expect(r3).not.toBeNull();
    expect(r3!.isFlap).toBeUndefined();
  });

  it('detects flapping at threshold', () => {
    tracker.checkState('service:A', 'service', 'stopped');   // new
    tracker.checkState('service:A', 'service', 'running');   // transition 1
    tracker.checkState('service:A', 'service', 'stopped');   // transition 2
    tracker.checkState('service:A', 'service', 'running');   // transition 3
    const flap = tracker.checkState('service:A', 'service', 'stopped'); // transition 4

    expect(flap).not.toBeNull();
    expect(flap!.isFlap).toBe(true);
    expect(flap!.toState).toBe('flapping');
  });

  it('suppresses further transitions during flapping', () => {
    tracker.checkState('service:A', 'service', 'stopped');
    tracker.checkState('service:A', 'service', 'running');
    tracker.checkState('service:A', 'service', 'stopped');
    tracker.checkState('service:A', 'service', 'running');
    tracker.checkState('service:A', 'service', 'stopped'); // flap detected

    // Further changes should return null (suppressed)
    const suppressed = tracker.checkState('service:A', 'service', 'running');
    expect(suppressed).toBeNull();
  });

  it('getFlappingResources returns only flapping resources', () => {
    tracker.checkState('service:A', 'service', 'stopped');
    tracker.checkState('service:A', 'service', 'running');
    tracker.checkState('service:A', 'service', 'stopped');
    tracker.checkState('service:A', 'service', 'running');
    tracker.checkState('service:A', 'service', 'stopped'); // flap

    tracker.checkState('service:B', 'service', 'stopped'); // not flapping

    const flapping = tracker.getFlappingResources();
    expect(flapping).toHaveLength(1);
    expect(flapping[0].resourceId).toBe('service:A');
  });

  it('checkFlapStability clears flapping after stable period', () => {
    tracker.checkState('service:A', 'service', 'stopped');
    tracker.checkState('service:A', 'service', 'running');
    tracker.checkState('service:A', 'service', 'stopped');
    tracker.checkState('service:A', 'service', 'running');
    tracker.checkState('service:A', 'service', 'stopped'); // flap detected

    // Backdate the last transition to simulate stable period elapsed
    const state = tracker.getResourceState('service:A')!;
    const lastTrans = state.transitionHistory[state.transitionHistory.length - 1];
    lastTrans.timestamp = new Date(Date.now() - 2 * 60000).toISOString(); // 2 min ago

    const stable = tracker.checkFlapStability();
    expect(stable).toContain('service:A');
    expect(tracker.getFlappingResources()).toHaveLength(0);
  });
});

// ============================================
// DEPENDENCY AWARENESS
// ============================================

describe('StateTracker - Dependency Awareness', () => {
  it('isDownstreamOfDownParent returns false when no dependencies', () => {
    const result = tracker.isDownstreamOfDownParent('SomeService');
    expect(result.isDownstream).toBe(false);
    expect(result.downParents).toHaveLength(0);
  });

  it('detects when parent service is down', () => {
    // Manually set the dependency map (since we can't run PowerShell in tests)
    const depMap = tracker.getDependencyMap();
    depMap.serviceDependencies['ChildSvc'] = ['ParentSvc'];
    depMap.serviceDependents['ParentSvc'] = ['ChildSvc'];
    // Use the internal state by re-creating with persisted data
    // Instead, set parent as down through checkState
    tracker.checkState('service:ParentSvc', 'service', 'stopped');

    // Now manually inject dependency map (access private via any cast)
    (tracker as any).dependencyMap = {
      serviceDependencies: { ChildSvc: ['ParentSvc'] },
      serviceDependents: { ParentSvc: ['ChildSvc'] },
      lastRefreshed: new Date().toISOString()
    };

    const result = tracker.isDownstreamOfDownParent('ChildSvc');
    expect(result.isDownstream).toBe(true);
    expect(result.downParents).toContain('ParentSvc');
  });

  it('does not flag downstream when parent is running', () => {
    tracker.checkState('service:ParentSvc', 'service', 'running');

    (tracker as any).dependencyMap = {
      serviceDependencies: { ChildSvc: ['ParentSvc'] },
      serviceDependents: { ParentSvc: ['ChildSvc'] },
      lastRefreshed: new Date().toISOString()
    };

    const result = tracker.isDownstreamOfDownParent('ChildSvc');
    expect(result.isDownstream).toBe(false);
  });

  it('getParentDependencies and getDependentServices work correctly', () => {
    (tracker as any).dependencyMap = {
      serviceDependencies: { ChildA: ['Parent1', 'Parent2'], ChildB: ['Parent1'] },
      serviceDependents: { Parent1: ['ChildA', 'ChildB'], Parent2: ['ChildA'] },
      lastRefreshed: new Date().toISOString()
    };

    expect(tracker.getParentDependencies('ChildA')).toEqual(['Parent1', 'Parent2']);
    expect(tracker.getDependentServices('Parent1')).toEqual(['ChildA', 'ChildB']);
    expect(tracker.getParentDependencies('Unknown')).toEqual([]);
  });
});

// ============================================
// SUMMARY
// ============================================

describe('StateTracker - Summary', () => {
  it('returns correct summary counts', () => {
    tracker.checkState('service:A', 'service', 'stopped', 'warning');
    tracker.checkState('service:B', 'service', 'running', 'info');
    tracker.checkState('metric:cpu', 'metric', 'critical', 'high');

    // Manually set escalation checkpoint for metric:cpu
    const state = tracker.getResourceState('metric:cpu')!;
    state.escalationCheckpoints.high = new Date().toISOString();

    const summary = tracker.getSummary();
    expect(summary.activeIssues).toBe(2); // stopped + critical
    expect(summary.flapping).toBe(0);
    expect(summary.escalatedSeverities).toBe(1); // metric:cpu has high checkpoint
  });
});
