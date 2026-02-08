import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { MaintenanceWindowManager, MaintenanceWindow } from '../src/service/maintenance-windows';

const mockLogger: any = {
  info: jest.fn(),
  warn: jest.fn(),
  debug: jest.fn(),
  error: jest.fn(),
};

let tmpDir: string;
let manager: MaintenanceWindowManager;

function makeWindow(overrides: Partial<MaintenanceWindow> = {}): MaintenanceWindow {
  const now = new Date();
  return {
    id: 'mw-1',
    name: 'Test Window',
    startTime: new Date(now.getTime() - 60000).toISOString(), // started 1 min ago
    endTime: new Date(now.getTime() + 3600000).toISOString(), // ends in 1 hour
    scope: { type: 'all' },
    suppressEscalation: true,
    suppressRemediation: true,
    createdBy: 'technician',
    createdAt: now.toISOString(),
    ...overrides,
  };
}

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opsis-mw-test-'));
  mockLogger.info.mockClear();
  mockLogger.warn.mockClear();
  mockLogger.debug.mockClear();
  manager = new MaintenanceWindowManager(mockLogger, tmpDir);
});

afterEach(() => {
  manager.stopExpirationChecks();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

// ============================================
// WINDOW MANAGEMENT
// ============================================

describe('MaintenanceWindowManager - Window Management', () => {
  it('adds a window and retrieves it', () => {
    manager.addWindow(makeWindow());
    expect(manager.getAllWindows()).toHaveLength(1);
    expect(manager.getAllWindows()[0].id).toBe('mw-1');
  });

  it('replaces window with same ID on add', () => {
    manager.addWindow(makeWindow({ name: 'First' }));
    manager.addWindow(makeWindow({ name: 'Updated' }));

    expect(manager.getAllWindows()).toHaveLength(1);
    expect(manager.getAllWindows()[0].name).toBe('Updated');
  });

  it('removes a window by ID', () => {
    manager.addWindow(makeWindow());
    manager.removeWindow('mw-1');
    expect(manager.getAllWindows()).toHaveLength(0);
  });

  it('removeWindow is a no-op for unknown ID', () => {
    manager.addWindow(makeWindow());
    manager.removeWindow('unknown-id');
    expect(manager.getAllWindows()).toHaveLength(1);
  });

  it('getActiveWindows filters by time', () => {
    // Active window
    manager.addWindow(makeWindow({ id: 'active' }));
    // Future window (not yet started)
    manager.addWindow(makeWindow({
      id: 'future',
      startTime: new Date(Date.now() + 3600000).toISOString(),
      endTime: new Date(Date.now() + 7200000).toISOString(),
    }));
    // Past window (already ended)
    manager.addWindow(makeWindow({
      id: 'past',
      startTime: new Date(Date.now() - 7200000).toISOString(),
      endTime: new Date(Date.now() - 3600000).toISOString(),
    }));

    const active = manager.getActiveWindows();
    expect(active).toHaveLength(1);
    expect(active[0].id).toBe('active');
  });
});

// ============================================
// MAINTENANCE CHECK - SCOPE MATCHING
// ============================================

describe('MaintenanceWindowManager - Scope Matching', () => {
  it('scope=all suppresses everything', () => {
    manager.addWindow(makeWindow({ scope: { type: 'all' } }));

    const result = manager.isUnderMaintenance('service-health', 'W32Time', 'signal-123');
    expect(result.suppressed).toBe(true);
    expect(result.reason).toContain('Maintenance window');
  });

  it('scope=services matches by service name', () => {
    manager.addWindow(makeWindow({
      scope: { type: 'services', services: ['W32Time', 'Spooler'] }
    }));

    expect(manager.isUnderMaintenance('service-health', 'W32Time').suppressed).toBe(true);
    expect(manager.isUnderMaintenance('service-health', 'Spooler').suppressed).toBe(true);
    expect(manager.isUnderMaintenance('service-health', 'OtherSvc').suppressed).toBe(false);
  });

  it('scope=categories matches by signal category', () => {
    manager.addWindow(makeWindow({
      scope: { type: 'categories', categories: ['disk-health', 'memory'] }
    }));

    expect(manager.isUnderMaintenance('disk-health').suppressed).toBe(true);
    expect(manager.isUnderMaintenance('memory').suppressed).toBe(true);
    expect(manager.isUnderMaintenance('cpu').suppressed).toBe(false);
  });

  it('scope=specific matches by signal ID', () => {
    manager.addWindow(makeWindow({
      scope: { type: 'specific', signalIds: ['sig-abc', 'sig-def'] }
    }));

    expect(manager.isUnderMaintenance('any', undefined, 'sig-abc').suppressed).toBe(true);
    expect(manager.isUnderMaintenance('any', undefined, 'sig-xyz').suppressed).toBe(false);
  });

  it('expired window does not suppress', () => {
    manager.addWindow(makeWindow({
      startTime: new Date(Date.now() - 7200000).toISOString(),
      endTime: new Date(Date.now() - 3600000).toISOString(),
    }));

    expect(manager.isUnderMaintenance('service-health').suppressed).toBe(false);
  });

  it('future window does not suppress', () => {
    manager.addWindow(makeWindow({
      startTime: new Date(Date.now() + 3600000).toISOString(),
      endTime: new Date(Date.now() + 7200000).toISOString(),
    }));

    expect(manager.isUnderMaintenance('service-health').suppressed).toBe(false);
  });

  it('overlapping windows - any active match suppresses', () => {
    // Window 1: services scope, doesn't match
    manager.addWindow(makeWindow({
      id: 'mw-1',
      scope: { type: 'services', services: ['Spooler'] }
    }));
    // Window 2: all scope, matches
    manager.addWindow(makeWindow({
      id: 'mw-2',
      scope: { type: 'all' }
    }));

    const result = manager.isUnderMaintenance('cpu', 'W32Time');
    expect(result.suppressed).toBe(true);
  });
});

// ============================================
// PERSISTENCE
// ============================================

describe('MaintenanceWindowManager - Persistence', () => {
  it('persists windows to disk and loads on new instance', () => {
    manager.addWindow(makeWindow({ id: 'persist-test', name: 'Persist' }));

    const manager2 = new MaintenanceWindowManager(mockLogger, tmpDir);
    const windows = manager2.getAllWindows();
    expect(windows).toHaveLength(1);
    expect(windows[0].id).toBe('persist-test');
    expect(windows[0].name).toBe('Persist');
  });

  it('handles missing file gracefully', () => {
    const emptyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opsis-mw-empty-'));
    const m = new MaintenanceWindowManager(mockLogger, emptyDir);
    expect(m.getAllWindows()).toHaveLength(0);
    fs.rmSync(emptyDir, { recursive: true, force: true });
  });
});

// ============================================
// EXPIRATION
// ============================================

describe('MaintenanceWindowManager - Expiration', () => {
  it('onExpiration callback is registered', () => {
    const cb = jest.fn();
    manager.onExpiration(cb);

    // Access private to verify (the callback gets invoked through checkExpirations)
    expect((manager as any).onWindowExpiredCallback).toBe(cb);
  });

  it('startExpirationChecks is idempotent', () => {
    manager.startExpirationChecks();
    const timer1 = (manager as any).expirationTimer;
    manager.startExpirationChecks();
    const timer2 = (manager as any).expirationTimer;
    expect(timer1).toBe(timer2); // Same timer, not duplicated
  });

  it('stopExpirationChecks clears timer', () => {
    manager.startExpirationChecks();
    expect((manager as any).expirationTimer).not.toBeNull();
    manager.stopExpirationChecks();
    expect((manager as any).expirationTimer).toBeNull();
  });
});
