import { WMIInterface, ProcessInfo, ServiceInfo, DiskInfo } from './wmi-interface';
import Logger from '../core/logger';

export interface SystemMetrics {
  cpu: number;
  memory: {
    total_mb: number;
    used_mb: number;
    free_mb: number;
    used_percent: number;
  };
  disk: DiskInfo[];
  processes: ProcessInfo[];
  services: ServiceInfo[];
  timestamp: string;
}

export class SystemMonitor {
  private wmi: WMIInterface;
  private logger: Logger;

  constructor(logger: Logger) {
    this.wmi = new WMIInterface();
    this.logger = logger;
  }

  async collectMetrics(): Promise<SystemMetrics> {
    try {
      // Await ALL WMI calls properly
      const [cpu, memory, disk, processes, services] = await Promise.all([
        this.wmi.getCPU(),
        this.wmi.getMemory(),
        this.wmi.getDisk(),
        this.wmi.getProcesses(),
        this.wmi.getServices()
      ]);

      return {
        cpu,
        memory,
        disk,
        processes,
        services,
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      this.logger.error('Failed to collect metrics', { error: error.message });
      
      // Return safe defaults on error
      return {
        cpu: 0,
        memory: {
          total_mb: 0,
          used_mb: 0,
          free_mb: 0,
          used_percent: 0
        },
        disk: [],
        processes: [],
        services: [],
        timestamp: new Date().toISOString()
      };
    }
  }
}
