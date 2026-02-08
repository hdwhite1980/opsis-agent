// maintenance-windows.ts - Maintenance window management for suppressing alerts during planned work
import * as fs from 'fs';
import * as path from 'path';
import { Logger } from '../common/logger';

// ============================================
// INTERFACES
// ============================================

export interface MaintenanceScope {
  type: 'all' | 'services' | 'categories' | 'specific';
  services?: string[];
  categories?: string[];
  signalIds?: string[];
}

export interface MaintenanceWindow {
  id: string;
  name: string;
  startTime: string;
  endTime: string;
  scope: MaintenanceScope;
  suppressEscalation: boolean;
  suppressRemediation: boolean;
  createdBy: 'server' | 'technician' | 'schedule';
  createdAt: string;
}

export interface MaintenanceCheckResult {
  suppressed: boolean;
  window?: MaintenanceWindow;
  reason?: string;
}

interface MaintenanceWindowsData {
  windows: MaintenanceWindow[];
  version: string;
}

// ============================================
// MAINTENANCE WINDOW MANAGER
// ============================================

export class MaintenanceWindowManager {
  private logger: Logger;
  private filePath: string;
  private windows: MaintenanceWindow[] = [];
  private expirationTimer: NodeJS.Timeout | null = null;
  private onWindowExpiredCallback?: (window: MaintenanceWindow) => void;
  private readonly CLEANUP_AGE_DAYS = 7;

  constructor(logger: Logger, dataDir: string) {
    this.logger = logger;
    this.filePath = path.join(dataDir, 'maintenance-windows.json');
    this.load();
  }

  // ============================================
  // WINDOW MANAGEMENT
  // ============================================

  public addWindow(window: MaintenanceWindow): void {
    // Remove any existing window with same ID
    this.windows = this.windows.filter(w => w.id !== window.id);
    this.windows.push(window);

    this.logger.info('Maintenance window added', {
      id: window.id,
      name: window.name,
      start: window.startTime,
      end: window.endTime,
      scope: window.scope.type,
      createdBy: window.createdBy
    });

    this.save();
  }

  public removeWindow(id: string): void {
    const before = this.windows.length;
    this.windows = this.windows.filter(w => w.id !== id);

    if (this.windows.length < before) {
      this.logger.info('Maintenance window removed', { id });
      this.save();
    }
  }

  public getActiveWindows(): MaintenanceWindow[] {
    const now = new Date();
    return this.windows.filter(w => {
      const start = new Date(w.startTime);
      const end = new Date(w.endTime);
      return now >= start && now <= end;
    });
  }

  public getAllWindows(): MaintenanceWindow[] {
    return [...this.windows];
  }

  // ============================================
  // MAINTENANCE CHECK
  // ============================================

  public isUnderMaintenance(
    signalCategory: string,
    serviceName?: string,
    signalId?: string
  ): MaintenanceCheckResult {
    const now = new Date();

    for (const window of this.windows) {
      const start = new Date(window.startTime);
      const end = new Date(window.endTime);

      if (now < start || now > end) continue;

      const scope = window.scope;

      if (scope.type === 'all') {
        return {
          suppressed: true,
          window,
          reason: `Maintenance window: ${window.name}`
        };
      }

      if (scope.type === 'services' && serviceName && scope.services) {
        if (scope.services.includes(serviceName)) {
          return {
            suppressed: true,
            window,
            reason: `Service ${serviceName} under maintenance: ${window.name}`
          };
        }
      }

      if (scope.type === 'categories' && scope.categories) {
        if (scope.categories.includes(signalCategory)) {
          return {
            suppressed: true,
            window,
            reason: `Category ${signalCategory} under maintenance: ${window.name}`
          };
        }
      }

      if (scope.type === 'specific' && signalId && scope.signalIds) {
        if (scope.signalIds.includes(signalId)) {
          return {
            suppressed: true,
            window,
            reason: `Signal ${signalId} under maintenance: ${window.name}`
          };
        }
      }
    }

    return { suppressed: false };
  }

  // ============================================
  // EXPIRATION MANAGEMENT
  // ============================================

  public onExpiration(callback: (window: MaintenanceWindow) => void): void {
    this.onWindowExpiredCallback = callback;
  }

  public startExpirationChecks(): void {
    if (this.expirationTimer) return;

    this.expirationTimer = setInterval(() => {
      this.checkExpirations();
    }, 30000);
  }

  public stopExpirationChecks(): void {
    if (this.expirationTimer) {
      clearInterval(this.expirationTimer);
      this.expirationTimer = null;
    }
  }

  private checkExpirations(): void {
    const now = new Date();
    const expired: MaintenanceWindow[] = [];

    for (const window of this.windows) {
      const end = new Date(window.endTime);
      // Window just expired (within the last 30s check interval)
      if (now > end && (now.getTime() - end.getTime()) < 35000) {
        expired.push(window);
      }
    }

    for (const window of expired) {
      this.logger.info('Maintenance window expired', {
        id: window.id,
        name: window.name
      });

      if (this.onWindowExpiredCallback) {
        this.onWindowExpiredCallback(window);
      }
    }

    // Cleanup old expired windows
    this.cleanupExpiredWindows();
  }

  private cleanupExpiredWindows(): void {
    const cutoff = Date.now() - (this.CLEANUP_AGE_DAYS * 24 * 60 * 60 * 1000);
    const before = this.windows.length;

    this.windows = this.windows.filter(w => {
      const end = new Date(w.endTime);
      return end.getTime() > cutoff;
    });

    if (this.windows.length < before) {
      this.logger.debug('Cleaned up expired maintenance windows', {
        removed: before - this.windows.length
      });
      this.save();
    }
  }

  // ============================================
  // PERSISTENCE
  // ============================================

  private load(): void {
    try {
      if (fs.existsSync(this.filePath)) {
        const raw = fs.readFileSync(this.filePath, 'utf-8');
        const data: MaintenanceWindowsData = JSON.parse(raw);
        this.windows = data.windows || [];
        this.logger.info('Maintenance windows loaded', { count: this.windows.length });
      }
    } catch (error: any) {
      this.logger.warn('Failed to load maintenance windows', { error: error.message });
    }
  }

  private save(): void {
    try {
      const data: MaintenanceWindowsData = {
        windows: this.windows,
        version: '1.0.0'
      };
      fs.writeFileSync(this.filePath, JSON.stringify(data, null, 2), { mode: 0o600 });
    } catch (error: any) {
      this.logger.warn('Failed to save maintenance windows', { error: error.message });
    }
  }
}
