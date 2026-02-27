// system-monitor.ts - Comprehensive System Health Monitoring
// Monitors ALL 12 categories of signals from your requirements

import * as os from 'os';
import { exec } from 'child_process';
import { promisify } from 'util';
import { Logger } from '../common/logger';
import { BehavioralProfiler } from './behavioral-profiler';

const execAsync = promisify(exec);

export interface SystemSignal {
  id: string;
  category: string; // performance, storage, services, network, security, updates, etc.
  severity: 'critical' | 'warning' | 'info';
  metric: string;
  value: any;
  threshold?: any;
  message: string;
  timestamp: Date;
  metadata?: Record<string, any>;
  // For ticket creation
  eventId?: number;
  eventSource?: string;
  // For hardware health scoring
  componentType?: 'disk' | 'cpu' | 'memory' | 'motherboard';
}

export type MonitorCallback = (signal: SystemSignal) => void;

export class SystemMonitor {
  private logger: Logger;
  private isMonitoring: boolean = false;
  private monitoringIntervals: NodeJS.Timeout[] = [];
  private onSignalDetected: MonitorCallback;
  
  // Baselines for anomaly detection
  private baselines: Map<string, any> = new Map();
  private historicalData: Map<string, any[]> = new Map();
  private signalCounts: Map<string, number> = new Map();

  // Sustained threshold tracking: metric -> consecutive count above threshold
  private consecutiveBreaches: Map<string, number> = new Map();
  private readonly SUSTAINED_THRESHOLD_COUNT = 3; // Require 3 consecutive breaches

  // Behavioral profiler for temporal anomaly detection
  private profiler: BehavioralProfiler | null = null;

  // Absolute critical ceilings — never suppressed regardless of profile
  private readonly CRITICAL_CEILING_CPU = 98;
  private readonly CRITICAL_CEILING_MEMORY = 95;
  private readonly CRITICAL_CEILING_DISK_FREE = 3;

  // Server-configurable thresholds (defaults overridden by welcome message)
  private thresholds = {
    cpu_warning: 75,
    cpu_critical: 90,
    memory_warning: 80,
    memory_critical: 90,
    disk_warning: 20,
    disk_critical: 10
  };

  /**
   * Update thresholds from server configuration.
   */
  public updateThresholds(newThresholds: Record<string, number>): void {
    if (newThresholds.cpu_warning != null) this.thresholds.cpu_warning = newThresholds.cpu_warning;
    if (newThresholds.cpu_critical != null) this.thresholds.cpu_critical = newThresholds.cpu_critical;
    if (newThresholds.memory_warning != null) this.thresholds.memory_warning = newThresholds.memory_warning;
    if (newThresholds.memory_critical != null) this.thresholds.memory_critical = newThresholds.memory_critical;
    if (newThresholds.disk_warning != null) this.thresholds.disk_warning = newThresholds.disk_warning;
    if (newThresholds.disk_critical != null) this.thresholds.disk_critical = newThresholds.disk_critical;
    this.logger.info('Thresholds updated from server', this.thresholds);
  }

  /**
   * Attach a behavioral profiler for temporal anomaly detection.
   * When set, the monitor feeds samples to the profiler and consults it
   * before emitting signals to suppress false positives.
   */
  public setProfiler(profiler: BehavioralProfiler): void {
    this.profiler = profiler;
    this.logger.info('Behavioral profiler attached to system monitor');
  }

  constructor(logger: Logger, onSignalDetected: MonitorCallback) {
    this.logger = logger;
    this.onSignalDetected = onSignalDetected;
  }

  public start(): void {
    if (this.isMonitoring) {
      this.logger.warn('System monitor already running');
      return;
    }

    this.isMonitoring = true;
    this.logger.info('Starting comprehensive system monitoring (12 categories)...');

    // ===== CATEGORY 1: HARDWARE RESOURCES =====
    this.scheduleMonitor(() => this.monitorCPU(), 30000);              // Every 30s
    this.scheduleMonitor(() => this.monitorMemory(), 30000);           // Every 30s
    this.scheduleMonitor(() => this.monitorDisk(), 60000);             // Every 60s
    this.scheduleMonitor(() => this.monitorPower(), 60000);            // Every 60s

    // ===== CATEGORY 2: OPERATING SYSTEM =====
    this.scheduleMonitor(() => this.monitorServices(), 30000);         // Every 30s
    this.scheduleMonitor(() => this.monitorUpdates(), 300000);         // Every 5min
    this.scheduleMonitor(() => this.monitorSystemHealth(), 120000);    // Every 2min

    // ===== CATEGORY 3: APPLICATIONS =====
    this.scheduleMonitor(() => this.monitorApplications(), 60000);     // Every 60s
    this.scheduleMonitor(() => this.monitorProcesses(), 30000);        // Every 30s

    // ===== CATEGORY 4: NETWORK & CONNECTIVITY =====
    this.scheduleMonitor(() => this.monitorNetwork(), 30000);          // Every 30s
    this.scheduleMonitor(() => this.monitorDNS(), 60000);              // Every 60s

    // ===== CATEGORY 5: SECURITY & CONFIGURATION =====
    this.scheduleMonitor(() => this.monitorSecurity(), 300000);        // Every 5min
    this.scheduleMonitor(() => this.monitorFirewall(), 300000);        // Every 5min

    // ===== CATEGORY 6: HARDWARE HEALTH & FAILURE PREDICTION =====
    this.scheduleMonitor(() => this.monitorSMART(), 300000);            // Every 5min
    this.scheduleMonitor(() => this.monitorTemperature(), 60000);       // Every 60s
    this.scheduleMonitor(() => this.monitorMemoryErrors(), 300000);     // Every 5min
    this.scheduleMonitor(() => this.monitorDiskIO(), 60000);            // Every 60s
    this.scheduleMonitor(() => this.monitorCrashDumps(), 300000);       // Every 5min

    // ===== CATEGORY 7: TIME SYNCHRONIZATION =====
    this.scheduleMonitor(() => this.monitorNtpSync(), 300000);          // Every 5min

    this.logger.info('All 18 monitoring categories started');
  }

  public stop(): void {
    this.isMonitoring = false;
    this.monitoringIntervals.forEach(interval => clearInterval(interval));
    this.monitoringIntervals = [];
    this.logger.info('System monitoring stopped');
  }

  private scheduleMonitor(fn: () => Promise<void>, intervalMs: number): void {
    // Run immediately on startup
    setTimeout(() => {
      fn().catch(err => this.logger.error('Monitor startup error', err));
    }, 5000); // Wait 5s for service to fully start
    
    // Then schedule recurring
    const interval = setInterval(() => {
      fn().catch(err => this.logger.error('Monitor error', err));
    }, intervalMs);
    
    this.monitoringIntervals.push(interval);
  }

  // ============================================
  // CATEGORY 1: HARDWARE RESOURCES - CPU
  // ============================================

  private async monitorCPU(): Promise<void> {
    try {
      // Overall CPU usage
      const cpuUsage = await this.getCPUUsage();

      // Feed behavioral profiler
      this.profiler?.recordSample('system:cpu', cpuUsage);

      // Profiler check happens BEFORE sustained breach counting.
      // If the profiler says "within_normal", the sample doesn't count as a breach
      // at all — the consecutive counter resets, preserving sustained detection integrity.
      const cpuProfileAnomalous = cpuUsage >= this.CRITICAL_CEILING_CPU || this.isProfileAnomalous('system:cpu', cpuUsage);

      const cpuCriticalBreach = cpuUsage > this.thresholds.cpu_critical && cpuProfileAnomalous;
      const cpuWarningBreach = cpuUsage > this.thresholds.cpu_warning && cpuProfileAnomalous;

      if (this.isSustainedBreach('cpu-critical', cpuCriticalBreach)) {
        this.emitSignal({
          id: 'cpu-critical',
          category: 'performance',
          severity: 'critical',
          metric: 'cpu_usage',
          value: cpuUsage,
          threshold: this.thresholds.cpu_critical,
          message: `CPU usage sustained critically high: ${cpuUsage.toFixed(1)}%`,
          timestamp: new Date(),
          eventId: 2001,
          eventSource: 'OPSIS-SystemMonitor'
        });
      } else if (this.isSustainedBreach('cpu-high', cpuWarningBreach)) {
        this.emitSignal({
          id: 'cpu-high',
          category: 'performance',
          severity: 'warning',
          metric: 'cpu_usage',
          value: cpuUsage,
          threshold: this.thresholds.cpu_warning,
          message: `CPU usage sustained elevated: ${cpuUsage.toFixed(1)}%`,
          timestamp: new Date(),
          eventId: 2002,
          eventSource: 'OPSIS-SystemMonitor'
        });
      }

      // Per-process CPU monitoring
      const topProcesses = await this.getTopCPUProcesses();

      // Feed process snapshots to profiler
      this.profiler?.recordProcessSnapshot(
        topProcesses.map(p => ({ name: p.name, cpu: p.cpu, memoryMB: 0 }))
      );

      for (const proc of topProcesses.slice(0, 3)) {
        if (proc.cpu > 50) {
          // Check per-process behavioral profile before alerting
          if (!this.isProfileAnomalous(`process:${proc.name.toLowerCase()}:cpu`, proc.cpu)) {
            this.logger.debug('Process CPU alert suppressed by behavioral profile', { process: proc.name, cpu: proc.cpu });
            continue;
          }
          this.emitSignal({
            id: `process-cpu-${proc.pid}`,
            category: 'performance',
            severity: 'warning',
            metric: 'process_cpu',
            value: proc.cpu,
            threshold: 50,
            message: `Process ${proc.name} consuming ${proc.cpu.toFixed(1)}% CPU`,
            timestamp: new Date(),
            metadata: {
              processName: proc.name,
              pid: proc.pid,
              process_path: proc.path,
              process_company: proc.company,
              command_line: proc.command_line
            },
            eventId: 2003,
            eventSource: 'OPSIS-SystemMonitor'
          });
        }
      }

      this.updateBaseline('cpu_usage', cpuUsage);
    } catch (error) {
      this.logger.error('CPU monitoring error', error);
    }
  }

  public async getCPUUsage(): Promise<number> {
    try {
      const { stdout } = await execAsync(
        'powershell -Command "(Get-Counter \'\\\\Processor(_Total)\\\\% Processor Time\').CounterSamples.CookedValue"',
        { timeout: 10000 }
      );
      return Math.min(100, Math.max(0, parseFloat(stdout.trim())));
    } catch {
      return 0;
    }
  }

  private async getTopCPUProcesses(): Promise<Array<{name: string, pid: number, cpu: number, path?: string, company?: string, command_line?: string}>> {
    try {
      const { stdout } = await execAsync(
        `powershell -NoProfile -Command "$cpuCores = (Get-CimInstance Win32_Processor).NumberOfLogicalProcessors; $cim = @{}; Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object { $cim[$_.ProcessId] = $_ }; Get-Process | Where-Object {$_.Id -ne 0} | Sort-Object CPU -Descending | Select-Object -First 5 | ForEach-Object { $c = $cim[$_.Id]; [PSCustomObject]@{ Name=$_.ProcessName; Id=$_.Id; CPUPercent=[math]::Round(($_.CPU / ((Get-Date) - $_.StartTime).TotalSeconds) * 100 / $cpuCores, 2); Path=$_.Path; Company=$_.Company; CommandLine=if($c){$c.CommandLine} } } | ConvertTo-Json"`,
        { timeout: 15000 }
      );
      const processes = JSON.parse(stdout || '[]');
      return Array.isArray(processes) ? processes.map(p => ({
        name: p.Name || 'Unknown',
        pid: p.Id || 0,
        cpu: p.CPUPercent || 0,
        path: p.Path || undefined,
        company: p.Company || undefined,
        command_line: p.CommandLine ? p.CommandLine.substring(0, 500) : undefined
      })) : [];
    } catch {
      return [];
    }
  }

  // ============================================
  // CATEGORY 1: HARDWARE RESOURCES - MEMORY
  // ============================================

  private async monitorMemory(): Promise<void> {
    try {
      const totalMem = os.totalmem();
      const freeMem = os.freemem();
      const usedMem = totalMem - freeMem;
      const usedPercent = (usedMem / totalMem) * 100;

      // Feed behavioral profiler
      this.profiler?.recordSample('system:memory', usedPercent);

      // Profiler check before sustained breach counting — if "within_normal",
      // the sample doesn't count as a breach and the consecutive counter resets.
      const memProfileAnomalous = usedPercent >= this.CRITICAL_CEILING_MEMORY || this.isProfileAnomalous('system:memory', usedPercent);

      const memCriticalBreach = usedPercent > this.thresholds.memory_critical && memProfileAnomalous;
      const memWarningBreach = usedPercent > this.thresholds.memory_warning && memProfileAnomalous;

      if (this.isSustainedBreach('memory-critical', memCriticalBreach)) {
        this.emitSignal({
          id: 'memory-critical',
          category: 'performance',
          severity: 'critical',
          metric: 'memory_usage',
          value: usedPercent,
          threshold: this.thresholds.memory_critical,
          message: `Memory usage sustained critical: ${usedPercent.toFixed(1)}% (${(freeMem / 1024 / 1024 / 1024).toFixed(2)}GB free)`,
          timestamp: new Date(),
          metadata: {
            totalGB: (totalMem / 1024 / 1024 / 1024).toFixed(2),
            freeGB: (freeMem / 1024 / 1024 / 1024).toFixed(2),
            usedGB: (usedMem / 1024 / 1024 / 1024).toFixed(2)
          },
          eventId: 2010,
          eventSource: 'OPSIS-SystemMonitor'
        });
      } else if (this.isSustainedBreach('memory-high', memWarningBreach)) {
        this.emitSignal({
          id: 'memory-high',
          category: 'performance',
          severity: 'warning',
          metric: 'memory_usage',
          value: usedPercent,
          threshold: this.thresholds.memory_warning,
          message: `Memory usage sustained high: ${usedPercent.toFixed(1)}%`,
          timestamp: new Date(),
          eventId: 2011,
          eventSource: 'OPSIS-SystemMonitor'
        });
      }

      // Memory pressure detection
      const topMemProcesses = await this.getTopMemoryProcesses();

      // Feed process memory snapshots to profiler
      this.profiler?.recordProcessSnapshot(
        topMemProcesses.map(p => ({ name: p.name, cpu: 0, memoryMB: p.memoryMB }))
      );

      for (const proc of topMemProcesses.slice(0, 3)) {
        if (proc.memoryMB > 2000) {
          // Check per-process behavioral profile before alerting
          if (!this.isProfileAnomalous(`process:${proc.name.toLowerCase()}:memory`, proc.memoryMB)) {
            this.logger.debug('Process memory alert suppressed by behavioral profile', { process: proc.name, memoryMB: proc.memoryMB });
            continue;
          }
          this.emitSignal({
            id: `process-memory-${proc.pid}`,
            category: 'performance',
            severity: 'warning',
            metric: 'process_memory',
            value: proc.memoryMB,
            threshold: 2000,
            message: `Process ${proc.name} using ${proc.memoryMB.toFixed(0)}MB memory`,
            timestamp: new Date(),
            metadata: {
              processName: proc.name,
              pid: proc.pid,
              process_path: proc.path,
              process_company: proc.company,
              command_line: proc.command_line
            },
            eventId: 2012,
            eventSource: 'OPSIS-SystemMonitor'
          });
        }
      }

      this.updateBaseline('memory_usage', usedPercent);
    } catch (error) {
      this.logger.error('Memory monitoring error', error);
    }
  }

  private async getTopMemoryProcesses(): Promise<Array<{name: string, pid: number, memoryMB: number, path?: string, company?: string, command_line?: string}>> {
    try {
      const { stdout } = await execAsync(
        `powershell -NoProfile -Command "$cim = @{}; Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object { $cim[$_.ProcessId] = $_ }; Get-Process | Where-Object {$_.WS -gt 0} | Sort-Object WS -Descending | Select-Object -First 5 | ForEach-Object { $c = $cim[$_.Id]; [PSCustomObject]@{ Name=$_.ProcessName; Id=$_.Id; WS=$_.WS; Path=$_.Path; Company=$_.Company; CommandLine=if($c){$c.CommandLine} } } | ConvertTo-Json"`,
        { timeout: 10000 }
      );
      const processes = JSON.parse(stdout || '[]');
      return Array.isArray(processes) ? processes.map(p => ({
        name: p.Name || 'Unknown',
        pid: p.Id || 0,
        memoryMB: (p.WS || 0) / 1024 / 1024,
        path: p.Path || undefined,
        company: p.Company || undefined,
        command_line: p.CommandLine ? p.CommandLine.substring(0, 500) : undefined
      })) : [];
    } catch {
      return [];
    }
  }

  // ============================================
  // CATEGORY 1: HARDWARE RESOURCES - DISK
  // ============================================

  private async monitorDisk(): Promise<void> {
    try {
      const { stdout } = await execAsync(
        'powershell -Command "Get-PSDrive -PSProvider FileSystem | Where-Object {$_.Used -ne $null} | Select-Object Name,@{N=\'Used\';E={$_.Used}},@{N=\'Free\';E={$_.Free}} | ConvertTo-Json"',
        { timeout: 15000 }
      );
      
      const drives = JSON.parse(stdout || '[]');
      const driveArray = Array.isArray(drives) ? drives : [drives];

      for (const drive of driveArray) {
        if (!drive.Used || !drive.Free) continue;

        const total = drive.Used + drive.Free;
        const freePercent = (drive.Free / total) * 100;

        // Feed behavioral profiler with disk free %
        this.profiler?.recordSample(`system:disk:${drive.Name}`, freePercent);

        if (freePercent < 10) {
          // Critical ceiling: always emit at < 3% free regardless of profile
          if (freePercent < this.CRITICAL_CEILING_DISK_FREE || this.isProfileAnomalous(`system:disk:${drive.Name}`, freePercent)) {
            this.emitSignal({
              id: `disk-critical-${drive.Name}`,
              category: 'storage',
              severity: 'critical',
              metric: 'disk_free',
              value: freePercent,
              threshold: 10,
              message: `Drive ${drive.Name}: critically low space (${freePercent.toFixed(1)}% free, ${(drive.Free / 1024 / 1024 / 1024).toFixed(2)}GB remaining)`,
              timestamp: new Date(),
              metadata: {
                drive: drive.Name,
                freeGB: (drive.Free / 1024 / 1024 / 1024).toFixed(2),
                totalGB: (total / 1024 / 1024 / 1024).toFixed(2)
              },
              eventId: 2020,
              eventSource: 'OPSIS-SystemMonitor'
            });
          } else {
            this.logger.debug('Disk critical alert suppressed by behavioral profile', { drive: drive.Name, freePercent });
          }
        } else if (freePercent < 20) {
          if (this.isProfileAnomalous(`system:disk:${drive.Name}`, freePercent)) {
            this.emitSignal({
              id: `disk-low-${drive.Name}`,
              category: 'storage',
              severity: 'warning',
              metric: 'disk_free',
              value: freePercent,
              threshold: 20,
              message: `Drive ${drive.Name}: low space (${freePercent.toFixed(1)}% free)`,
              timestamp: new Date(),
              metadata: { drive: drive.Name },
              eventId: 2021,
              eventSource: 'OPSIS-SystemMonitor'
            });
          } else {
            this.logger.debug('Disk warning alert suppressed by behavioral profile', { drive: drive.Name, freePercent });
          }
        }
      }

      // Check disk health
      await this.checkDiskHealth();

    } catch (error) {
      this.logger.error('Disk monitoring error', error);
    }
  }

  private async checkDiskHealth(): Promise<void> {
    try {
      const { stdout } = await execAsync(
        'powershell -Command "Get-PhysicalDisk | Select-Object FriendlyName,HealthStatus,OperationalStatus | ConvertTo-Json"',
        { timeout: 10000 }
      );
      
      const disks = JSON.parse(stdout || '[]');
      const diskArray = Array.isArray(disks) ? disks : [disks];

      for (const disk of diskArray) {
        if (disk.HealthStatus && disk.HealthStatus !== 'Healthy') {
          this.emitSignal({
            id: `disk-unhealthy-${disk.FriendlyName}`,
            category: 'storage',
            severity: 'critical',
            metric: 'disk_health',
            value: disk.HealthStatus,
            message: `Disk ${disk.FriendlyName} health: ${disk.HealthStatus}`,
            timestamp: new Date(),
            metadata: {
              disk: disk.FriendlyName,
              health: disk.HealthStatus,
              status: disk.OperationalStatus
            },
            eventId: 2022,
            eventSource: 'OPSIS-SystemMonitor'
          });
        }
      }
    } catch {
      // SMART not available
    }
  }

  // ============================================
  // CATEGORY 1: HARDWARE RESOURCES - POWER
  // ============================================

  private async monitorPower(): Promise<void> {
    try {
      const { stdout } = await execAsync(
        'powershell -Command "Get-WmiObject -Class Win32_Battery | Select-Object BatteryStatus,EstimatedChargeRemaining,EstimatedRunTime | ConvertTo-Json"',
        { timeout: 10000 }
      );

      if (stdout.trim()) {
        const battery = JSON.parse(stdout);
        
        if (battery.EstimatedChargeRemaining < 15) {
          this.emitSignal({
            id: 'battery-critical',
            category: 'power',
            severity: 'critical',
            metric: 'battery_level',
            value: battery.EstimatedChargeRemaining,
            threshold: 15,
            message: `Battery critically low: ${battery.EstimatedChargeRemaining}%`,
            timestamp: new Date(),
            metadata: {
              charge: battery.EstimatedChargeRemaining,
              status: battery.BatteryStatus,
              runtime: battery.EstimatedRunTime
            },
            eventId: 2030,
            eventSource: 'OPSIS-SystemMonitor'
          });
        } else if (battery.EstimatedChargeRemaining < 25) {
          this.emitSignal({
            id: 'battery-low',
            category: 'power',
            severity: 'warning',
            metric: 'battery_level',
            value: battery.EstimatedChargeRemaining,
            threshold: 25,
            message: `Battery low: ${battery.EstimatedChargeRemaining}%`,
            timestamp: new Date(),
            eventId: 2031,
            eventSource: 'OPSIS-SystemMonitor'
          });
        }
      }
    } catch {
      // Not a laptop or battery not accessible
    }
  }

  // ============================================
  // CATEGORY 2: OPERATING SYSTEM - SERVICES
  // ============================================

  private async monitorServices(): Promise<void> {
    try {
      const { stdout } = await execAsync(
        'powershell -Command "Get-Service | Where-Object {$_.StartType -eq \'Automatic\' -and $_.Status -ne \'Running\'} | Select-Object Name,DisplayName,Status,StartType | ConvertTo-Json"',
        { timeout: 15000 }
      );

      const services = stdout.trim() ? JSON.parse(stdout) : [];
      const serviceArray = Array.isArray(services) ? services : services ? [services] : [];

      for (const service of serviceArray) {
        const priority = this.getServicePriority(service.Name);

        // Optional services: log only, don't escalate
        if (priority === 'optional') {
          this.logger.debug('Skipping optional service', { name: service.Name, priority });
          continue;
        }

        this.emitSignal({
          id: `service-stopped-${service.Name}`,
          category: 'services',
          severity: priority === 'critical' ? 'critical' : 'warning',
          metric: 'service_status',
          value: 'stopped',
          message: `Service ${service.DisplayName || service.Name} stopped (StartType: ${service.StartType})`,
          timestamp: new Date(),
          metadata: {
            serviceName: service.Name,
            displayName: service.DisplayName,
            status: service.Status,
            startType: service.StartType,
            priority
          },
          eventId: 7034,
          eventSource: 'Service Control Manager'
        });
      }

    } catch (error) {
      this.logger.error('Services monitoring error', error);
    }
  }

  private getServicePriority(name: string): 'critical' | 'normal' | 'optional' {
    const critical = [
      'Spooler', 'W32Time', 'Dnscache', 'LanmanWorkstation', 'LanmanServer',
      'BITS', 'wuauserv', 'gpsvc', 'Schedule', 'EventLog', 'Winmgmt',
      'CryptSvc', 'RpcSs', 'RpcEptMapper', 'DcomLaunch', 'BFE', 'mpssvc'
    ];
    const optional = [
      'edgeupdate', 'edgeupdatem', 'MapsBroker', 'TabletInputService',
      'Fax', 'RemoteRegistry', 'WSearch', 'GoogleUpdate', 'AdobeUpdate',
      'DiagTrack', 'dmwappushservice', 'sppsvc', 'SysMain', 'WbioSrvc',
      'WerSvc', 'wisvc', 'InstallService', 'uhssvc', 'UsoSvc'
    ];
    if (critical.includes(name)) return 'critical';
    if (optional.includes(name)) return 'optional';
    return 'normal';
  }

  private isKnownStoppedService(name: string): boolean {
    return this.getServicePriority(name) === 'optional';
  }

  // ============================================
  // CATEGORY 2: OPERATING SYSTEM - UPDATES
  // ============================================

  private async monitorUpdates(): Promise<void> {
    try {
      // Check for pending updates
      const { stdout } = await execAsync(
        'powershell -Command "$updates = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search(\'IsInstalled=0 and IsHidden=0\'); $updates.Updates.Count"',
        { timeout: 30000 }
      );

      const pendingCount = parseInt(stdout.trim() || '0');
      
      if (pendingCount > 20) {
        this.emitSignal({
          id: 'updates-many-pending',
          category: 'updates',
          severity: 'warning',
          metric: 'pending_updates',
          value: pendingCount,
          threshold: 20,
          message: `${pendingCount} Windows updates pending installation`,
          timestamp: new Date(),
          metadata: { count: pendingCount },
          eventId: 2040,
          eventSource: 'OPSIS-SystemMonitor'
        });
      } else if (pendingCount > 0) {
        this.emitSignal({
          id: 'updates-pending',
          category: 'updates',
          severity: 'info',
          metric: 'pending_updates',
          value: pendingCount,
          message: `${pendingCount} Windows updates available`,
          timestamp: new Date(),
          metadata: { count: pendingCount },
          eventId: 2041,
          eventSource: 'OPSIS-SystemMonitor'
        });
      }

      // Check last update time
      await this.checkLastUpdateTime();

    } catch (error) {
      this.logger.error('Updates monitoring error', error);
    }
  }

  private async checkLastUpdateTime(): Promise<void> {
    try {
      const { stdout } = await execAsync(
        'powershell -Command "$session = New-Object -ComObject Microsoft.Update.Session; $history = $session.CreateUpdateSearcher().QueryHistory(0,1); if ($history.Count -gt 0) { $history | Select-Object -First 1 -ExpandProperty Date | Get-Date -Format o }"',
        { timeout: 20000 }
      );

      if (stdout.trim()) {
        const lastUpdate = new Date(stdout.trim());
        const daysSince = Math.floor((Date.now() - lastUpdate.getTime()) / (1000 * 60 * 60 * 24));

        if (daysSince > 60) {
          this.emitSignal({
            id: 'updates-overdue',
            category: 'updates',
            severity: 'warning',
            metric: 'days_since_update',
            value: daysSince,
            threshold: 60,
            message: `No Windows updates in ${daysSince} days (last: ${lastUpdate.toLocaleDateString()})`,
            timestamp: new Date(),
            metadata: { lastUpdate: lastUpdate.toISOString(), daysSince },
            eventId: 2042,
            eventSource: 'OPSIS-SystemMonitor'
          });
        }
      }
    } catch {
      // Update history not available
    }
  }

  // ============================================
  // CATEGORY 2: OPERATING SYSTEM - SYSTEM HEALTH
  // ============================================

  private async monitorSystemHealth(): Promise<void> {
    try {
      // Check uptime (detect if reboot needed)
      const uptimeHours = os.uptime() / 3600;
      
      if (uptimeHours > 720) { // 30 days
        this.emitSignal({
          id: 'reboot-needed',
          category: 'system',
          severity: 'warning',
          metric: 'uptime_hours',
          value: uptimeHours,
          threshold: 720,
          message: `System uptime: ${Math.floor(uptimeHours / 24)} days - reboot recommended`,
          timestamp: new Date(),
          metadata: { uptimeDays: Math.floor(uptimeHours / 24) },
          eventId: 2050,
          eventSource: 'OPSIS-SystemMonitor'
        });
      }

      // Check for pending reboot
      await this.checkPendingReboot();

    } catch (error) {
      this.logger.error('System health monitoring error', error);
    }
  }

  private async checkPendingReboot(): Promise<void> {
    try {
      const { stdout } = await execAsync(
        'powershell -Command "Test-Path \'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending\'"',
        { timeout: 5000 }
      );

      if (stdout.trim() === 'True') {
        this.emitSignal({
          id: 'reboot-pending',
          category: 'system',
          severity: 'warning',
          metric: 'reboot_required',
          value: true,
          message: 'System restart required to complete updates',
          timestamp: new Date(),
          eventId: 2051,
          eventSource: 'OPSIS-SystemMonitor'
        });
      }
    } catch {
      // Check failed
    }
  }

  // ============================================
  // CATEGORY 3: APPLICATIONS
  // ============================================

  private async monitorApplications(): Promise<void> {
    try {
      // Check recent application crashes
      const { stdout } = await execAsync(
        'powershell -Command "Get-EventLog -LogName Application -EntryType Error -Newest 20 -After (Get-Date).AddMinutes(-2) -ErrorAction SilentlyContinue | Where-Object {$_.EventID -in @(1000,1001,1002)} | Select-Object TimeGenerated,EventID,Source,Message | ConvertTo-Json"',
        { timeout: 15000 }
      );

      if (stdout.trim()) {
        const events = JSON.parse(stdout);
        const eventArray = Array.isArray(events) ? events : [events];

        for (const event of eventArray) {
          // Extract app name from message
          const appMatch = event.Message.match(/application name: ([^,]+)/i);
          const appName = appMatch ? appMatch[1].trim() : event.Source;

          this.emitSignal({
            id: `app-crash-${event.TimeGenerated}`,
            category: 'applications',
            severity: 'warning',
            metric: 'app_crash',
            value: true,
            message: `Application crash: ${appName}`,
            timestamp: new Date(event.TimeGenerated),
            metadata: {
              app: appName,
              source: event.Source,
              eventId: event.EventID,
              message: event.Message.substring(0, 200)
            },
            eventId: event.EventID,
            eventSource: 'Application'
          });
        }
      }

    } catch {
      // Event log might not be accessible
    }
  }

  // ============================================
  // CATEGORY 4: PROCESSES
  // ============================================

  private async monitorProcesses(): Promise<void> {
    try {
      // Check for hung/not responding processes
      const { stdout } = await execAsync(
        `powershell -NoProfile -Command "$cim = @{}; Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object { $cim[$_.ProcessId] = $_ }; Get-Process | Where-Object {$_.Responding -eq $false} | ForEach-Object { $c = $cim[$_.Id]; [PSCustomObject]@{ Name=$_.ProcessName; Id=$_.Id; StartTime=$_.StartTime; Path=$_.Path; Company=$_.Company; CommandLine=if($c){$c.CommandLine} } } | ConvertTo-Json"`,
        { timeout: 15000 }
      );

      if (stdout.trim()) {
        const processes = JSON.parse(stdout);
        const procArray = Array.isArray(processes) ? processes : [processes];

        for (const proc of procArray) {
          this.emitSignal({
            id: `process-hung-${proc.Id}`,
            category: 'processes',
            severity: 'warning',
            metric: 'process_responsive',
            value: false,
            message: `Process ${proc.Name} (PID ${proc.Id}) not responding`,
            timestamp: new Date(),
            metadata: {
              processName: proc.Name,
              pid: proc.Id,
              startTime: proc.StartTime,
              process_path: proc.Path || undefined,
              process_company: proc.Company || undefined,
              command_line: proc.CommandLine ? proc.CommandLine.substring(0, 500) : undefined
            },
            eventId: 2060,
            eventSource: 'OPSIS-SystemMonitor'
          });
        }
      }

    } catch (error) {
      this.logger.error('Process monitoring error', error);
    }
  }

  // ============================================
  // CATEGORY 5: NETWORK & CONNECTIVITY
  // ============================================

  private async monitorNetwork(): Promise<void> {
    try {
      // Test internet connectivity
      const { stdout } = await execAsync(
        'powershell -Command "Test-Connection -ComputerName 8.8.8.8 -Count 1 -Quiet"',
        { timeout: 10000 }
      );

      if (stdout.trim() === 'False') {
        this.emitSignal({
          id: 'network-offline',
          category: 'network',
          severity: 'critical',
          metric: 'network_connectivity',
          value: false,
          message: 'Network connectivity lost - cannot reach internet',
          timestamp: new Date(),
          eventId: 2070,
          eventSource: 'OPSIS-SystemMonitor'
        });
      }

      // Check gateway connectivity
      await this.checkGateway();

    } catch (error) {
      this.emitSignal({
        id: 'network-timeout',
        category: 'network',
        severity: 'critical',
        metric: 'network_timeout',
        value: true,
        message: 'Network connectivity test timed out',
        timestamp: new Date(),
        eventId: 2071,
        eventSource: 'OPSIS-SystemMonitor'
      });
    }
  }

  private async checkGateway(): Promise<void> {
    try {
      const { stdout } = await execAsync(
        'powershell -Command "Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Select-Object -ExpandProperty NextHop"',
        { timeout: 5000 }
      );

      const gateway = stdout.trim();
      if (gateway) {
        const { stdout: pingResult } = await execAsync(
          `powershell -Command "Test-Connection -ComputerName ${gateway} -Count 1 -Quiet"`,
          { timeout: 5000 }
        );

        if (pingResult.trim() === 'False') {
          this.emitSignal({
            id: 'gateway-unreachable',
            category: 'network',
            severity: 'critical',
            metric: 'gateway_reachable',
            value: false,
            message: `Default gateway ${gateway} unreachable`,
            timestamp: new Date(),
            metadata: { gateway },
            eventId: 2072,
            eventSource: 'OPSIS-SystemMonitor'
          });
        }
      }
    } catch {
      // Gateway check failed
    }
  }

  // ============================================
  // CATEGORY 5: DNS
  // ============================================

  private async monitorDNS(): Promise<void> {
    try {
      const { stdout } = await execAsync(
        'powershell -Command "Resolve-DnsName google.com -ErrorAction SilentlyContinue | Select-Object -First 1 Name"',
        { timeout: 10000 }
      );

      if (!stdout.trim()) {
        this.emitSignal({
          id: 'dns-failure',
          category: 'network',
          severity: 'warning',
          metric: 'dns_resolution',
          value: false,
          message: 'DNS resolution failing - cannot resolve domain names',
          timestamp: new Date(),
          eventId: 1014, // Windows DNS Event ID
          eventSource: 'DNS Client'
        });
      }

    } catch {
      this.emitSignal({
        id: 'dns-timeout',
        category: 'network',
        severity: 'warning',
        metric: 'dns_timeout',
        value: true,
        message: 'DNS resolution timed out',
        timestamp: new Date(),
        eventId: 1015,
        eventSource: 'DNS Client'
      });
    }
  }

  // ============================================
  // CATEGORY 6: SECURITY - DEFENDER
  // ============================================

  private async monitorSecurity(): Promise<void> {
    try {
      const { stdout } = await execAsync(
        'powershell -Command "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,IoavProtectionEnabled,OnAccessProtectionEnabled | ConvertTo-Json"',
        { timeout: 15000 }
      );

      const defender = JSON.parse(stdout);
      
      if (!defender.AntivirusEnabled) {
        this.emitSignal({
          id: 'defender-disabled',
          category: 'security',
          severity: 'critical',
          metric: 'antivirus_enabled',
          value: false,
          message: 'Windows Defender antivirus is disabled',
          timestamp: new Date(),
          eventId: 2080,
          eventSource: 'OPSIS-SystemMonitor'
        });
      }

      if (!defender.RealTimeProtectionEnabled) {
        this.emitSignal({
          id: 'defender-realtime-disabled',
          category: 'security',
          severity: 'critical',
          metric: 'realtime_protection',
          value: false,
          message: 'Windows Defender real-time protection is disabled',
          timestamp: new Date(),
          metadata: defender,
          eventId: 2081,
          eventSource: 'OPSIS-SystemMonitor'
        });
      }

    } catch (error) {
      // Security monitoring may fail if:
      // - Windows Defender not installed (some enterprise environments)
      // - Insufficient permissions
      // - Running on non-Windows OS
      // Silently skip rather than logging errors every 5 minutes
      this.logger.debug('Security monitoring skipped (may require admin rights or Defender not installed)');
    }
  }

  // ============================================
  // CATEGORY 6: SECURITY - FIREWALL
  // ============================================

  private async monitorFirewall(): Promise<void> {
    try {
      const { stdout } = await execAsync(
        'powershell -Command "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json"',
        { timeout: 10000 }
      );

      const profiles = JSON.parse(stdout);
      const profileArray = Array.isArray(profiles) ? profiles : [profiles];

      for (const profile of profileArray) {
        if (!profile.Enabled) {
          this.emitSignal({
            id: `firewall-disabled-${profile.Name}`,
            category: 'security',
            severity: 'warning',
            metric: 'firewall_enabled',
            value: false,
            message: `Windows Firewall disabled for ${profile.Name} profile`,
            timestamp: new Date(),
            metadata: { profile: profile.Name },
            eventId: 2082,
            eventSource: 'OPSIS-SystemMonitor'
          });
        }
      }

    } catch (error) {
      // Firewall monitoring may fail if insufficient permissions
      this.logger.debug('Firewall monitoring skipped (may require admin rights)');
    }
  }

  // ============================================
  // BASELINE & ANOMALY DETECTION
  // ============================================

  private getBaseline(key: string): any {
    return this.baselines.get(key);
  }

  private updateBaseline(key: string, value: any): void {
    if (!this.historicalData.has(key)) {
      this.historicalData.set(key, []);
    }
    
    const history = this.historicalData.get(key)!;
    history.push({ value, timestamp: Date.now() });
    
    // Keep last 100 samples (rolling window)
    if (history.length > 100) {
      history.shift();
    }
    
    // Calculate baseline (rolling average for numbers)
    if (typeof value === 'number') {
      const avg = history.reduce((sum, h) => sum + h.value, 0) / history.length;
      this.baselines.set(key, avg);
    } else {
      this.baselines.set(key, value);
    }
  }

  /**
   * Check if a metric value is anomalous according to the behavioral profile.
   * Returns true if the signal SHOULD be emitted (anomalous or insufficient data).
   * Returns false if the signal should be suppressed (within normal behavior).
   */
  private isProfileAnomalous(metricKey: string, value: number): boolean {
    if (!this.profiler) return true; // No profiler → emit signal (current behavior)

    const result = this.profiler.isAnomalous(metricKey, value);

    if (result.reason === 'within_normal') {
      this.profiler.recordSuppression(metricKey);
      return false; // Suppress: this is normal for this time of day
    }

    // 'anomalous' or 'insufficient_data' → emit signal
    return true;
  }

  /**
   * Track consecutive threshold breaches.
   * Returns true only after N consecutive breaches (sustained issue).
   */
  private isSustainedBreach(metricKey: string, isBreaching: boolean): boolean {
    if (isBreaching) {
      const count = (this.consecutiveBreaches.get(metricKey) || 0) + 1;
      this.consecutiveBreaches.set(metricKey, count);
      return count >= this.SUSTAINED_THRESHOLD_COUNT;
    } else {
      this.consecutiveBreaches.set(metricKey, 0);
      return false;
    }
  }

  private emitSignal(signal: SystemSignal): void {
    // Deduplication: Don't emit same signal too frequently
    const key = `${signal.id}-${signal.severity}`;
    const lastCount = this.signalCounts.get(key) || 0;
    const now = Date.now();
    
    // Rate limit: Same signal max once per 5 minutes
    if (lastCount && (now - lastCount) < 300000) {
      return;
    }
    
    this.signalCounts.set(key, now);

    this.logger.debug('System signal detected', {
      id: signal.id,
      category: signal.category,
      severity: signal.severity,
      metric: signal.metric
    });

    this.onSignalDetected(signal);
  }

  // ============================================
  // CATEGORY 6: HARDWARE HEALTH & FAILURE PREDICTION
  // ============================================

  private async monitorSMART(): Promise<void> {
    try {
      const { stdout } = await execAsync(
        `powershell -NoProfile -Command "$disks = Get-PhysicalDisk -ErrorAction SilentlyContinue; foreach ($d in $disks) { $rel = Get-StorageReliabilityCounter -PhysicalDisk $d -ErrorAction SilentlyContinue; [PSCustomObject]@{ FriendlyName=$d.FriendlyName; DeviceId=$d.DeviceId; MediaType=$d.MediaType; HealthStatus=$d.HealthStatus; OperationalStatus=$d.OperationalStatus; ReadErrorsTotal=if($rel){$rel.ReadErrorsTotal}else{0}; WriteErrorsTotal=if($rel){$rel.WriteErrorsTotal}else{0}; Temperature=if($rel){$rel.Temperature}else{0}; Wear=if($rel){$rel.Wear}else{0}; PowerOnHours=if($rel){$rel.PowerOnHours}else{0} } } | ConvertTo-Json -Compress"`,
        { timeout: 30000 }
      );

      if (!stdout.trim()) return;

      const disks = Array.isArray(JSON.parse(stdout.trim())) ? JSON.parse(stdout.trim()) : [JSON.parse(stdout.trim())];

      for (const disk of disks) {
        const diskId = disk.DeviceId || '0';
        const meta = {
          DeviceId: diskId,
          FriendlyName: disk.FriendlyName,
          MediaType: disk.MediaType,
          HealthStatus: disk.HealthStatus,
          ReadErrors: disk.ReadErrorsTotal || 0,
          WriteErrors: disk.WriteErrorsTotal || 0,
          Temperature: disk.Temperature || 0,
          Wear: disk.Wear || 0,
          PowerOnHours: disk.PowerOnHours || 0
        };

        // Health status check
        if (disk.HealthStatus && disk.HealthStatus !== 'Healthy') {
          this.emitSignal({
            id: `smart-health-${diskId}`,
            category: 'hardware',
            severity: 'critical',
            metric: 'smart_health',
            value: disk.HealthStatus,
            message: `Disk ${disk.FriendlyName} health status: ${disk.HealthStatus}`,
            timestamp: new Date(),
            metadata: meta,
            componentType: 'disk'
          });
        }

        // Read/Write errors
        const totalErrors = (disk.ReadErrorsTotal || 0) + (disk.WriteErrorsTotal || 0);
        if (totalErrors > 0) {
          this.emitSignal({
            id: `smart-errors-${diskId}`,
            category: 'hardware',
            severity: totalErrors > 10 ? 'critical' : 'warning',
            metric: 'smart_errors',
            value: totalErrors,
            threshold: 0,
            message: `Disk ${disk.FriendlyName} has ${totalErrors} SMART errors (read: ${disk.ReadErrorsTotal || 0}, write: ${disk.WriteErrorsTotal || 0})`,
            timestamp: new Date(),
            metadata: meta,
            componentType: 'disk'
          });
        }

        // SSD Wear (only for SSDs)
        if (disk.MediaType === 'SSD' && disk.Wear != null && disk.Wear > 0) {
          const wearPct = disk.Wear;
          if (wearPct > 80) {
            this.emitSignal({
              id: `smart-wear-${diskId}`,
              category: 'hardware',
              severity: wearPct > 90 ? 'critical' : 'warning',
              metric: 'smart_wear',
              value: wearPct,
              threshold: 80,
              message: `SSD ${disk.FriendlyName} wear level at ${wearPct}%`,
              timestamp: new Date(),
              metadata: meta,
              componentType: 'disk'
            });
          }
        }

        // Disk temperature
        if (disk.Temperature && disk.Temperature > 0) {
          const tempC = disk.Temperature;
          if (tempC > 55) {
            this.emitSignal({
              id: `smart-temp-${diskId}`,
              category: 'hardware',
              severity: tempC > 65 ? 'critical' : 'warning',
              metric: 'disk_temperature',
              value: tempC,
              threshold: 55,
              message: `Disk ${disk.FriendlyName} temperature: ${tempC}°C`,
              timestamp: new Date(),
              metadata: meta,
              componentType: 'disk'
            });
          }
          this.updateBaseline(`disk_temp_${diskId}`, tempC);
        }

        // Power-on hours (informational, useful for failure prediction)
        if (disk.PowerOnHours && disk.PowerOnHours > 35000) {
          this.emitSignal({
            id: `smart-hours-${diskId}`,
            category: 'hardware',
            severity: disk.PowerOnHours > 50000 ? 'warning' : 'info',
            metric: 'power_on_hours',
            value: disk.PowerOnHours,
            threshold: 35000,
            message: `Disk ${disk.FriendlyName} has ${disk.PowerOnHours} power-on hours`,
            timestamp: new Date(),
            metadata: meta,
            componentType: 'disk'
          });
        }
      }
    } catch (error) {
      this.logger.debug('SMART monitoring not available', error);
    }
  }

  private async monitorTemperature(): Promise<void> {
    try {
      const { stdout } = await execAsync(
        `powershell -NoProfile -Command "Get-WmiObject -Namespace root/wmi -Class MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue | Select-Object InstanceName,CurrentTemperature | ConvertTo-Json -Compress"`,
        { timeout: 10000 }
      );

      if (!stdout.trim()) return;

      const zones = Array.isArray(JSON.parse(stdout.trim())) ? JSON.parse(stdout.trim()) : [JSON.parse(stdout.trim())];

      for (const zone of zones) {
        if (!zone.CurrentTemperature) continue;

        // WMI returns temperature in tenths of Kelvin
        const tempC = Math.round((zone.CurrentTemperature / 10) - 273.15);
        const zoneName = zone.InstanceName || 'unknown';

        this.updateBaseline(`cpu_temp_${zoneName}`, tempC);

        if (this.isSustainedBreach(`cpu-temp-critical-${zoneName}`, tempC > 90)) {
          this.emitSignal({
            id: `cpu-temp-critical`,
            category: 'hardware',
            severity: 'critical',
            metric: 'cpu_temperature',
            value: tempC,
            threshold: 90,
            message: `CPU temperature critically high: ${tempC}°C`,
            timestamp: new Date(),
            metadata: { zone: zoneName, temperatureC: tempC },
            componentType: 'cpu'
          });
        } else if (this.isSustainedBreach(`cpu-temp-high-${zoneName}`, tempC > 80)) {
          this.emitSignal({
            id: `cpu-temp-high`,
            category: 'hardware',
            severity: 'warning',
            metric: 'cpu_temperature',
            value: tempC,
            threshold: 80,
            message: `CPU temperature elevated: ${tempC}°C`,
            timestamp: new Date(),
            metadata: { zone: zoneName, temperatureC: tempC },
            componentType: 'cpu'
          });
        }
      }
    } catch (error) {
      this.logger.debug('Temperature monitoring not available (WMI thermal zone not supported on this hardware)');
    }
  }

  private async monitorMemoryErrors(): Promise<void> {
    try {
      const { stdout } = await execAsync(
        `powershell -NoProfile -Command "Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-WHEA-Logger'} -MaxEvents 10 -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -gt (Get-Date).AddMinutes(-10) } | Select-Object TimeCreated,Id,Message | ConvertTo-Json -Compress"`,
        { timeout: 15000 }
      );

      if (!stdout.trim()) return;

      const events = Array.isArray(JSON.parse(stdout.trim())) ? JSON.parse(stdout.trim()) : [JSON.parse(stdout.trim())];

      if (events.length > 0) {
        this.emitSignal({
          id: 'memory-ecc-error',
          category: 'hardware',
          severity: 'critical',
          metric: 'memory_errors',
          value: events.length,
          threshold: 0,
          message: `${events.length} hardware memory error(s) detected (WHEA). Possible RAM failure.`,
          timestamp: new Date(),
          metadata: {
            errorCount: events.length,
            latestError: events[0]?.Message?.substring(0, 200) || 'Unknown',
            eventIds: events.map((e: any) => e.Id)
          },
          componentType: 'memory'
        });
      }
    } catch (error) {
      this.logger.debug('Memory error monitoring: no WHEA events found');
    }
  }

  private async monitorDiskIO(): Promise<void> {
    try {
      const { stdout } = await execAsync(
        `powershell -NoProfile -Command "$samples = (Get-Counter '\\PhysicalDisk(*)\\Avg. Disk sec/Read','\\PhysicalDisk(*)\\Avg. Disk sec/Write','\\PhysicalDisk(*)\\Disk Bytes/sec' -ErrorAction SilentlyContinue).CounterSamples; $samples | Select-Object InstanceName,Path,CookedValue | ConvertTo-Json -Compress"`,
        { timeout: 15000 }
      );

      if (!stdout.trim()) return;

      const samples = Array.isArray(JSON.parse(stdout.trim())) ? JSON.parse(stdout.trim()) : [JSON.parse(stdout.trim())];

      // Group by instance
      const diskMetrics: Record<string, { readLatency?: number; writeLatency?: number; throughput?: number }> = {};

      for (const sample of samples) {
        if (!sample.InstanceName || sample.InstanceName === '_total') continue;
        const instance = sample.InstanceName;
        if (!diskMetrics[instance]) diskMetrics[instance] = {};

        const path = (sample.Path || '').toLowerCase();
        if (path.includes('sec/read')) {
          diskMetrics[instance].readLatency = (sample.CookedValue || 0) * 1000; // Convert to ms
        } else if (path.includes('sec/write')) {
          diskMetrics[instance].writeLatency = (sample.CookedValue || 0) * 1000;
        } else if (path.includes('bytes/sec')) {
          diskMetrics[instance].throughput = sample.CookedValue || 0;
        }
      }

      for (const [instance, metrics] of Object.entries(diskMetrics)) {
        const maxLatency = Math.max(metrics.readLatency || 0, metrics.writeLatency || 0);

        this.updateBaseline(`disk_io_latency_${instance}`, maxLatency);
        this.updateBaseline(`disk_io_throughput_${instance}`, metrics.throughput || 0);

        if (this.isSustainedBreach(`disk-io-critical-${instance}`, maxLatency > 100)) {
          this.emitSignal({
            id: `disk-io-latency-${instance}`,
            category: 'hardware',
            severity: 'critical',
            metric: 'disk_latency',
            value: maxLatency,
            threshold: 100,
            message: `Disk ${instance} latency critically high: ${maxLatency.toFixed(1)}ms`,
            timestamp: new Date(),
            metadata: {
              instance,
              readLatencyMs: metrics.readLatency?.toFixed(1),
              writeLatencyMs: metrics.writeLatency?.toFixed(1),
              throughputBps: metrics.throughput
            },
            componentType: 'disk'
          });
        } else if (this.isSustainedBreach(`disk-io-warning-${instance}`, maxLatency > 20)) {
          this.emitSignal({
            id: `disk-io-latency-${instance}`,
            category: 'hardware',
            severity: 'warning',
            metric: 'disk_latency',
            value: maxLatency,
            threshold: 20,
            message: `Disk ${instance} latency elevated: ${maxLatency.toFixed(1)}ms`,
            timestamp: new Date(),
            metadata: {
              instance,
              readLatencyMs: metrics.readLatency?.toFixed(1),
              writeLatencyMs: metrics.writeLatency?.toFixed(1),
              throughputBps: metrics.throughput
            },
            componentType: 'disk'
          });
        }
      }
    } catch (error) {
      this.logger.debug('Disk I/O monitoring error', error);
    }
  }

  private async monitorCrashDumps(): Promise<void> {
    try {
      // Check for recent minidumps (last 24 hours)
      const { stdout: minidumps } = await execAsync(
        `powershell -NoProfile -Command "Get-ChildItem 'C:\\Windows\\Minidump' -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-24) } | Select-Object Name,LastWriteTime,Length | ConvertTo-Json -Compress"`,
        { timeout: 10000 }
      );

      // Check for BugCheck events in System log (last 24 hours)
      const { stdout: bugchecks } = await execAsync(
        `powershell -NoProfile -Command "Get-WinEvent -FilterHashtable @{LogName='System'; Id=1001; ProviderName='Microsoft-Windows-WER-SystemErrorReporting'} -MaxEvents 5 -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -gt (Get-Date).AddHours(-24) } | Select-Object TimeCreated,Message | ConvertTo-Json -Compress"`,
        { timeout: 10000 }
      );

      let dumpCount = 0;
      let dumpFiles: string[] = [];

      if (minidumps.trim()) {
        const dumps = Array.isArray(JSON.parse(minidumps.trim())) ? JSON.parse(minidumps.trim()) : [JSON.parse(minidumps.trim())];
        dumpCount = dumps.length;
        dumpFiles = dumps.map((d: any) => d.Name);
      }

      let bugcheckCount = 0;
      let bugcheckMessages: string[] = [];

      if (bugchecks.trim()) {
        const checks = Array.isArray(JSON.parse(bugchecks.trim())) ? JSON.parse(bugchecks.trim()) : [JSON.parse(bugchecks.trim())];
        bugcheckCount = checks.length;
        bugcheckMessages = checks.map((c: any) => (c.Message || '').substring(0, 200));
      }

      if (dumpCount > 0 || bugcheckCount > 0) {
        this.emitSignal({
          id: 'bsod-detected',
          category: 'hardware',
          severity: 'critical',
          metric: 'crash_dump',
          value: dumpCount + bugcheckCount,
          threshold: 0,
          message: `BSOD detected: ${dumpCount} crash dump(s), ${bugcheckCount} BugCheck event(s) in last 24 hours`,
          timestamp: new Date(),
          metadata: {
            dumpFiles,
            dumpCount,
            bugcheckCount,
            bugcheckMessages
          },
          componentType: 'motherboard'
        });
      }
    } catch (error) {
      this.logger.debug('Crash dump monitoring error', error);
    }
  }

  // ============================================
  // CATEGORY 7: TIME SYNCHRONIZATION
  // ============================================

  private ntpSyncOk: boolean = true;

  public isNtpSyncOk(): boolean {
    return this.ntpSyncOk;
  }

  private async monitorNtpSync(): Promise<void> {
    try {
      const { stdout } = await execAsync(
        'powershell -NoProfile -Command "w32tm /query /status 2>$null | Out-String"',
        { timeout: 10000 }
      );

      const output = stdout || '';

      // Parse last sync time
      const lastSyncMatch = output.match(/Last Successful Sync Time:\s*(.*)/i);
      if (lastSyncMatch) {
        const lastSyncStr = lastSyncMatch[1].trim();
        const lastSync = new Date(lastSyncStr);
        const hoursSinceSync = (Date.now() - lastSync.getTime()) / (1000 * 60 * 60);

        if (hoursSinceSync > 1) {
          this.ntpSyncOk = false;
          this.emitSignal({
            id: 'ntp-sync-stale',
            category: 'security',
            severity: 'warning',
            metric: 'ntp_sync',
            value: Math.round(hoursSinceSync),
            threshold: 1,
            message: `NTP sync stale: last sync was ${Math.round(hoursSinceSync)} hours ago`,
            timestamp: new Date(),
            metadata: { lastSync: lastSyncStr, hoursSinceSync: Math.round(hoursSinceSync) }
          });
          return;
        }
      }

      // Parse clock offset (Phase Offset)
      const offsetMatch = output.match(/Phase Offset:\s*([0-9.e+-]+)s/i);
      if (offsetMatch) {
        const offsetSeconds = Math.abs(parseFloat(offsetMatch[1]));
        if (offsetSeconds > 30) {
          this.ntpSyncOk = false;
          this.emitSignal({
            id: 'ntp-clock-drift',
            category: 'security',
            severity: 'critical',
            metric: 'ntp_offset',
            value: offsetSeconds,
            threshold: 30,
            message: `Clock drift detected: ${offsetSeconds.toFixed(1)}s offset from NTP server`,
            timestamp: new Date(),
            metadata: { offsetSeconds }
          });
          return;
        }
      }

      this.ntpSyncOk = true;
    } catch (error) {
      this.logger.debug('NTP sync monitoring error', error);
      // Don't fail NTP status on monitoring errors — w32tm may not be running
    }
  }

  // ============================================
  // STATISTICS & REPORTING
  // ============================================

  public getMonitoringStats(): Record<string, any> {
    return {
      isMonitoring: this.isMonitoring,
      activeMonitors: this.monitoringIntervals.length,
      baselineCount: this.baselines.size,
      signalsSuppressed: this.signalCounts.size
    };
  }

  /**
   * Get disk usage stats for the primary (C:) drive.
   */
  public async getDiskStats(): Promise<{ usedPercent: number; freeGB: number }> {
    try {
      const { stdout } = await execAsync(
        'powershell -Command "Get-PSDrive -Name C -PSProvider FileSystem | Select-Object @{N=\'Used\';E={$_.Used}},@{N=\'Free\';E={$_.Free}} | ConvertTo-Json"',
        { timeout: 10000 }
      );
      const drive = JSON.parse(stdout || '{}');
      if (drive.Used != null && drive.Free != null) {
        const total = drive.Used + drive.Free;
        return {
          usedPercent: Math.round((drive.Used / total) * 1000) / 10,
          freeGB: Math.round((drive.Free / 1024 / 1024 / 1024) * 10) / 10
        };
      }
    } catch {
      // fallback
    }
    return { usedPercent: 0, freeGB: 0 };
  }

  /**
   * Get the number of running processes.
   */
  public async getProcessCount(): Promise<number> {
    try {
      const { stdout } = await execAsync(
        'powershell -Command "(Get-Process).Count"',
        { timeout: 10000 }
      );
      return parseInt(stdout.trim(), 10) || 0;
    } catch {
      return 0;
    }
  }

  /**
   * Get installed software with running status and resource usage.
   * Used for software inventory reporting.
   */
  public async getSoftwareInventory(): Promise<Array<{
    name: string;
    version: string;
    publisher: string;
    install_date: string;
    is_running: boolean;
    cpu_percent: number;
    memory_mb: number;
  }>> {
    try {
      // Get installed software from registry (both 64-bit and 32-bit)
      const { stdout: installedRaw } = await execAsync(
        `powershell -NoProfile -Command "$apps = @(); foreach ($path in 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*') { $apps += Get-ItemProperty $path -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and $_.DisplayName -ne '' } | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate }; $apps | Sort-Object DisplayName -Unique | ConvertTo-Json -Compress"`,
        { timeout: 30000 }
      );

      // Get running processes grouped by name with memory usage
      // Avoid CPU calculation in PS (unreliable for snapshots, and StartTime throws on system processes)
      const { stdout: processRaw } = await execAsync(
        `powershell -NoProfile -Command "Get-Process -ErrorAction SilentlyContinue | Where-Object {$_.Id -ne 0} | Group-Object -Property Name | ForEach-Object { $mem = 0; foreach ($p in $_.Group) { $mem += $p.WorkingSet64 }; [PSCustomObject]@{ Name=$_.Name; MemMB=[math]::Round($mem / 1MB, 1) } } | ConvertTo-Json -Compress"`,
        { timeout: 30000 }
      );

      const installed = JSON.parse(installedRaw || '[]');
      const installedArr: any[] = Array.isArray(installed) ? installed : [installed];

      const processes = JSON.parse(processRaw || '[]');
      const processArr: any[] = Array.isArray(processes) ? processes : [processes];

      // Build process lookup (lowercase name -> memory MB)
      const processMap = new Map<string, number>();
      for (const p of processArr) {
        if (p.Name) {
          processMap.set(p.Name.toLowerCase(), p.MemMB || 0);
        }
      }

      return installedArr.map(app => {
        const name = app.DisplayName || '';
        // Try to match installed software name to a running process
        const nameWords = name.toLowerCase().split(/[\s\-_]+/);
        let memMb: number | undefined = processMap.get(nameWords[0]);
        if (memMb == null && nameWords.length > 1) {
          memMb = processMap.get(nameWords.slice(0, 2).join(''));
        }
        if (memMb == null) {
          for (const [procName, procMem] of processMap) {
            if (procName.includes(nameWords[0]) && nameWords[0].length > 3) {
              memMb = procMem;
              break;
            }
          }
        }

        return {
          name,
          version: app.DisplayVersion || '',
          publisher: app.Publisher || '',
          install_date: app.InstallDate
            ? `${app.InstallDate.substring(0, 4)}-${app.InstallDate.substring(4, 6)}-${app.InstallDate.substring(6, 8)}`
            : '',
          is_running: memMb != null,
          cpu_percent: 0,
          memory_mb: memMb ?? 0
        };
      });
    } catch (error) {
      this.logger.error('Failed to collect software inventory', error);
      return [];
    }
  }
}
