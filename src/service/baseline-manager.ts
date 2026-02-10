import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { exec } from 'child_process';
import { promisify } from 'util';
import { Logger } from '../common/logger';

const execAsync = promisify(exec);

export interface SystemBaseline {
  captured_at: string;
  os: {
    version: string;
    build: string;
    architecture: string;
  };
  cpu: {
    average_usage: number;
    model: string;
    cores: number;
  };
  memory: {
    usage_percent: number;
    total_gb: number;
  };
  disks: Array<{
    drive: string;
    free_percent: number;
    total_gb: number;
  }>;
  top_processes: Array<{
    name: string;
    memory_mb: number;
  }>;
  services: {
    running_count: number;
    auto_start: string[];
  };
  startup_programs: string[];
  installed_software: Array<{
    name: string;
    version: string;
  }>;
  uptime_seconds: number;
}

export interface BaselineDiff {
  cpu_change: number | null;       // e.g., +45 means 45% higher than baseline
  memory_change: number | null;
  disk_changes: Array<{ drive: string; change: number }>;
  new_processes: string[];
  missing_services: string[];
  new_software: string[];
  removed_software: string[];
}

const BASELINE_MAX_AGE_MS = 24 * 60 * 60 * 1000; // 24 hours

export class BaselineManager {
  private logger: Logger;
  private baselinePath: string;
  private cachedBaseline: SystemBaseline | null = null;

  constructor(logger: Logger, dataDir: string) {
    this.logger = logger;
    this.baselinePath = path.join(dataDir, 'baseline.json');
  }

  async captureIfNeeded(): Promise<void> {
    try {
      const existing = this.loadBaseline();
      if (existing) {
        const age = Date.now() - new Date(existing.captured_at).getTime();
        if (age < BASELINE_MAX_AGE_MS) {
          this.logger.info('Baseline is current', {
            age_hours: Math.round(age / 3600000),
            captured_at: existing.captured_at
          });
          return;
        }
        this.logger.info('Baseline expired, recapturing', { age_hours: Math.round(age / 3600000) });
      } else {
        this.logger.info('No baseline found, capturing initial baseline');
      }

      await this.captureBaseline();
    } catch (error) {
      this.logger.error('Failed to capture baseline', error);
    }
  }

  async captureBaseline(): Promise<SystemBaseline> {
    this.logger.info('Capturing system baseline...');
    const start = Date.now();

    const [cpuAvg, memInfo, diskInfo, topProcs, serviceInfo, startupProgs, software] = await Promise.allSettled([
      this.getCpuAverage(),
      this.getMemoryInfo(),
      this.getDiskInfo(),
      this.getTopProcesses(),
      this.getServiceInfo(),
      this.getStartupPrograms(),
      this.getSoftwareList()
    ]);

    const baseline: SystemBaseline = {
      captured_at: new Date().toISOString(),
      os: {
        version: os.version?.() || os.release(),
        build: os.release(),
        architecture: os.arch()
      },
      cpu: {
        average_usage: cpuAvg.status === 'fulfilled' ? cpuAvg.value : 0,
        model: os.cpus()[0]?.model || 'Unknown',
        cores: os.cpus().length
      },
      memory: {
        usage_percent: memInfo.status === 'fulfilled' ? memInfo.value.usagePercent : 0,
        total_gb: Math.round(os.totalmem() / (1024 * 1024 * 1024) * 10) / 10
      },
      disks: diskInfo.status === 'fulfilled' ? diskInfo.value : [],
      top_processes: topProcs.status === 'fulfilled' ? topProcs.value : [],
      services: serviceInfo.status === 'fulfilled' ? serviceInfo.value : { running_count: 0, auto_start: [] },
      startup_programs: startupProgs.status === 'fulfilled' ? startupProgs.value : [],
      installed_software: software.status === 'fulfilled' ? software.value : [],
      uptime_seconds: os.uptime()
    };

    // Ensure data directory exists
    const dir = path.dirname(this.baselinePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    fs.writeFileSync(this.baselinePath, JSON.stringify(baseline, null, 2), 'utf8');
    this.cachedBaseline = baseline;

    const duration = Date.now() - start;
    this.logger.info('Baseline captured', {
      duration_ms: duration,
      cpu: baseline.cpu.average_usage,
      memory: baseline.memory.usage_percent,
      disks: baseline.disks.length,
      services: baseline.services.running_count,
      software: baseline.installed_software.length
    });

    return baseline;
  }

  getBaseline(): SystemBaseline | null {
    if (this.cachedBaseline) return this.cachedBaseline;
    return this.loadBaseline();
  }

  getBaselineDiff(currentMetrics: { cpu?: number; memory?: number; disks?: Array<{ drive: string; free_percent: number }> }): BaselineDiff | null {
    const baseline = this.getBaseline();
    if (!baseline) return null;

    const diff: BaselineDiff = {
      cpu_change: currentMetrics.cpu != null ? Math.round(currentMetrics.cpu - baseline.cpu.average_usage) : null,
      memory_change: currentMetrics.memory != null ? Math.round(currentMetrics.memory - baseline.memory.usage_percent) : null,
      disk_changes: [],
      new_processes: [],
      missing_services: [],
      new_software: [],
      removed_software: []
    };

    if (currentMetrics.disks) {
      for (const current of currentMetrics.disks) {
        const baselineDisk = baseline.disks.find(d => d.drive === current.drive);
        if (baselineDisk) {
          diff.disk_changes.push({
            drive: current.drive,
            change: Math.round(current.free_percent - baselineDisk.free_percent)
          });
        }
      }
    }

    return diff;
  }

  private loadBaseline(): SystemBaseline | null {
    try {
      if (!fs.existsSync(this.baselinePath)) return null;
      const raw = fs.readFileSync(this.baselinePath, 'utf8');
      const baseline = JSON.parse(raw) as SystemBaseline;
      this.cachedBaseline = baseline;
      return baseline;
    } catch {
      return null;
    }
  }

  private async getCpuAverage(): Promise<number> {
    // Take 3 samples 1 second apart for a more stable reading
    const samples: number[] = [];
    for (let i = 0; i < 3; i++) {
      const { stdout } = await execAsync(
        'powershell -Command "(Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average"',
        { timeout: 10000 }
      );
      const val = parseFloat(stdout.trim());
      if (!isNaN(val)) samples.push(val);
      if (i < 2) await new Promise(r => setTimeout(r, 1000));
    }
    return samples.length > 0 ? Math.round(samples.reduce((a, b) => a + b, 0) / samples.length) : 0;
  }

  private async getMemoryInfo(): Promise<{ usagePercent: number }> {
    const { stdout } = await execAsync(
      'powershell -Command "$os = Get-CimInstance Win32_OperatingSystem; [math]::Round(($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize * 100, 1)"',
      { timeout: 10000 }
    );
    return { usagePercent: parseFloat(stdout.trim()) || 0 };
  }

  private async getDiskInfo(): Promise<Array<{ drive: string; free_percent: number; total_gb: number }>> {
    const { stdout } = await execAsync(
      'powershell -Command "Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -ne $null } | ForEach-Object { $total = $_.Used + $_.Free; $freeP = if ($total -gt 0) { [math]::Round($_.Free / $total * 100, 1) } else { 0 }; $totalGB = [math]::Round($total / 1GB, 1); \\"$($_.Name)|$freeP|$totalGB\\" }"',
      { timeout: 15000 }
    );
    return stdout.trim().split('\n').filter(Boolean).map(line => {
      const [drive, freeStr, totalStr] = line.trim().split('|');
      return {
        drive: drive + ':',
        free_percent: parseFloat(freeStr) || 0,
        total_gb: parseFloat(totalStr) || 0
      };
    });
  }

  private async getTopProcesses(): Promise<Array<{ name: string; memory_mb: number }>> {
    const { stdout } = await execAsync(
      'powershell -Command "Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 10 | ForEach-Object { \\"$($_.ProcessName)|$([math]::Round($_.WorkingSet64 / 1MB, 1))\\" }"',
      { timeout: 15000 }
    );
    return stdout.trim().split('\n').filter(Boolean).map(line => {
      const [name, memStr] = line.trim().split('|');
      return { name, memory_mb: parseFloat(memStr) || 0 };
    });
  }

  private async getServiceInfo(): Promise<{ running_count: number; auto_start: string[] }> {
    const { stdout: countOut } = await execAsync(
      'powershell -Command "(Get-Service | Where-Object { $_.Status -eq \'Running\' }).Count"',
      { timeout: 10000 }
    );
    const { stdout: autoOut } = await execAsync(
      'powershell -Command "Get-Service | Where-Object { $_.StartType -eq \'Automatic\' } | Select-Object -ExpandProperty Name"',
      { timeout: 15000 }
    );
    return {
      running_count: parseInt(countOut.trim()) || 0,
      auto_start: autoOut.trim().split('\n').filter(Boolean).map(s => s.trim())
    };
  }

  private async getStartupPrograms(): Promise<string[]> {
    const { stdout } = await execAsync(
      'powershell -Command "Get-CimInstance Win32_StartupCommand | Select-Object -ExpandProperty Name"',
      { timeout: 15000 }
    );
    return stdout.trim().split('\n').filter(Boolean).map(s => s.trim());
  }

  private async getSoftwareList(): Promise<Array<{ name: string; version: string }>> {
    const { stdout } = await execAsync(
      'powershell -Command "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Where-Object { $_.DisplayName } | Select-Object -First 100 | ForEach-Object { \\"$($_.DisplayName)|$($_.DisplayVersion)\\" }"',
      { timeout: 20000 }
    );
    return stdout.trim().split('\n').filter(Boolean).map(line => {
      const [name, version] = line.trim().split('|');
      return { name: name || 'Unknown', version: version || '' };
    });
  }
}
