import { execSync } from 'child_process';
import Logger from '../../common/logger';

export interface PrimitiveResult {
  success: boolean;
  output?: string;
  error?: string;
  duration_ms: number;
}

// Reject strings containing shell metacharacters to prevent injection
function validateShellInput(input: string, label: string): void {
  if (/[;&|`$><\r\n]/.test(input)) {
    throw new Error(`Invalid ${label}: contains shell metacharacters`);
  }
}

// Protected processes that must NEVER be killed
const PROTECTED_PROCESSES = new Set([
  'svchost.exe', 'lsass.exe', 'csrss.exe', 'winlogon.exe',
  'dwm.exe', 'explorer.exe', 'services.exe', 'smss.exe',
  'wininit.exe', 'system', 'system idle process',
  'conhost.exe', 'ntoskrnl.exe'
]);

const PROTECTED_SERVICES = new Set([
  'rpcss', 'dcomlaunch', 'lsm', 'samss', 'eventlog',
  'plugplay', 'power', 'winmgmt', 'cryptsvc',
  'lanmanserver', 'lanmanworkstation', 'schedule', 'w32time'
]);

export class Primitives {
  private logger: Logger;

  constructor(logger: Logger) {
    this.logger = logger;
  }
  
  // ========================================
  // PROCESS MANAGEMENT
  // ========================================
  
  async killProcessByName(processName: string): Promise<PrimitiveResult> {
    const startTime = Date.now();
    try {
      validateShellInput(processName, 'processName');
      if (PROTECTED_PROCESSES.has(processName.toLowerCase())) {
        return { success: false, error: `Cannot kill protected process: ${processName}`, duration_ms: Date.now() - startTime };
      }
      this.logger.info(`Killing process: ${processName}`);
      const output = execSync(`taskkill /F /IM "${processName}" /T`, { encoding: 'utf-8', timeout: 10000 });
      return { success: true, output, duration_ms: Date.now() - startTime };
    } catch (error: any) {
      return { success: false, error: error.message, duration_ms: Date.now() - startTime };
    }
  }
  
  async killProcessByPID(pid: number): Promise<PrimitiveResult> {
    const startTime = Date.now();
    try {
      this.logger.info(`Killing process PID: ${pid}`);
      const output = execSync(`taskkill /F /PID ${pid} /T`, { encoding: 'utf-8', timeout: 10000 });
      return { success: true, output, duration_ms: Date.now() - startTime };
    } catch (error: any) {
      return { success: false, error: error.message, duration_ms: Date.now() - startTime };
    }
  }
  
  async startProcess(processPath: string, args?: string): Promise<PrimitiveResult> {
    const startTime = Date.now();
    try {
      validateShellInput(processPath, 'processPath');
      if (args) validateShellInput(args, 'args');
      this.logger.info(`Starting process: ${processPath}`);
      const cmd = args ? `"${processPath}" ${args}` : `"${processPath}"`;
      execSync(`start "" ${cmd}`, { encoding: 'utf-8' });
      return { success: true, output: 'Process started', duration_ms: Date.now() - startTime };
    } catch (error: any) {
      return { success: false, error: error.message, duration_ms: Date.now() - startTime };
    }
  }
  
  // ========================================
  // SERVICE MANAGEMENT
  // ========================================
  
  async restartService(serviceName: string): Promise<PrimitiveResult> {
    const startTime = Date.now();
    try {
      validateShellInput(serviceName, 'serviceName');
      if (PROTECTED_SERVICES.has(serviceName.toLowerCase())) {
        return { success: false, error: `Cannot restart protected service: ${serviceName}`, duration_ms: Date.now() - startTime };
      }
      this.logger.info(`Restarting service: ${serviceName}`);
      try { execSync(`net stop "${serviceName}"`, { encoding: 'utf-8', timeout: 30000 }); } catch (e) {}
      await this.sleepInternal(2000);
      const output = execSync(`net start "${serviceName}"`, { encoding: 'utf-8', timeout: 30000 });
      return { success: true, output, duration_ms: Date.now() - startTime };
    } catch (error: any) {
      return { success: false, error: error.message, duration_ms: Date.now() - startTime };
    }
  }
  
  async startService(serviceName: string): Promise<PrimitiveResult> {
    const startTime = Date.now();
    try {
      validateShellInput(serviceName, 'serviceName');
      this.logger.info(`Starting service: ${serviceName}`);
      const output = execSync(`net start "${serviceName}"`, { encoding: 'utf-8', timeout: 30000 });
      return { success: true, output, duration_ms: Date.now() - startTime };
    } catch (error: any) {
      return { success: false, error: error.message, duration_ms: Date.now() - startTime };
    }
  }
  
  async stopService(serviceName: string): Promise<PrimitiveResult> {
    const startTime = Date.now();
    try {
      validateShellInput(serviceName, 'serviceName');
      if (PROTECTED_SERVICES.has(serviceName.toLowerCase())) {
        return { success: false, error: `Cannot stop protected service: ${serviceName}`, duration_ms: Date.now() - startTime };
      }
      this.logger.info(`Stopping service: ${serviceName}`);
      const output = execSync(`net stop "${serviceName}"`, { encoding: 'utf-8', timeout: 30000 });
      return { success: true, output, duration_ms: Date.now() - startTime };
    } catch (error: any) {
      return { success: false, error: error.message, duration_ms: Date.now() - startTime };
    }
  }
  
  // ========================================
  // DISK MANAGEMENT
  // ========================================
  
  async cleanTempFiles(): Promise<PrimitiveResult> {
    const startTime = Date.now();
    try {
      this.logger.info('Cleaning temp files');
      execSync('del /f /s /q %temp%\\*', { encoding: 'utf-8', timeout: 300000 });
      return { success: true, output: 'Temp files cleaned', duration_ms: Date.now() - startTime };
    } catch (error: any) {
      return { success: false, error: error.message, duration_ms: Date.now() - startTime };
    }
  }
  
  async emptyRecycleBin(): Promise<PrimitiveResult> {
    const startTime = Date.now();
    try {
      this.logger.info('Emptying recycle bin');
      execSync('rd /s /q %systemdrive%\\$Recycle.bin', { encoding: 'utf-8', timeout: 60000 });
      return { success: true, output: 'Recycle bin emptied', duration_ms: Date.now() - startTime };
    } catch (error: any) {
      return { success: false, error: error.message, duration_ms: Date.now() - startTime };
    }
  }
  
  async clearWindowsUpdateCache(): Promise<PrimitiveResult> {
    const startTime = Date.now();
    try {
      this.logger.info('Clearing Windows Update cache');
      execSync('net stop wuauserv', { encoding: 'utf-8' });
      execSync('del /f /s /q %systemroot%\\SoftwareDistribution\\*', { encoding: 'utf-8' });
      execSync('net start wuauserv', { encoding: 'utf-8' });
      return { success: true, output: 'Windows Update cache cleared', duration_ms: Date.now() - startTime };
    } catch (error: any) {
      return { success: false, error: error.message, duration_ms: Date.now() - startTime };
    }
  }
  
  // ========================================
  // NETWORK OPERATIONS
  // ========================================
  
  async flushDNS(): Promise<PrimitiveResult> {
    const startTime = Date.now();
    try {
      this.logger.info('Flushing DNS cache');
      const output = execSync('ipconfig /flushdns', { encoding: 'utf-8' });
      return { success: true, output, duration_ms: Date.now() - startTime };
    } catch (error: any) {
      return { success: false, error: error.message, duration_ms: Date.now() - startTime };
    }
  }
  
  async releaseIP(): Promise<PrimitiveResult> {
    const startTime = Date.now();
    try {
      this.logger.info('Releasing IP address');
      const output = execSync('ipconfig /release', { encoding: 'utf-8' });
      return { success: true, output, duration_ms: Date.now() - startTime };
    } catch (error: any) {
      return { success: false, error: error.message, duration_ms: Date.now() - startTime };
    }
  }
  
  async renewIP(): Promise<PrimitiveResult> {
    const startTime = Date.now();
    try {
      this.logger.info('Renewing IP address');
      const output = execSync('ipconfig /renew', { encoding: 'utf-8' });
      return { success: true, output, duration_ms: Date.now() - startTime };
    } catch (error: any) {
      return { success: false, error: error.message, duration_ms: Date.now() - startTime };
    }
  }
  
  async disableNetworkAdapter(adapterName: string): Promise<PrimitiveResult> {
    const startTime = Date.now();
    try {
      validateShellInput(adapterName, 'adapterName');
      this.logger.info(`Disabling network adapter: ${adapterName}`);
      const output = execSync(`netsh interface set interface "${adapterName}" disabled`, { encoding: 'utf-8' });
      return { success: true, output, duration_ms: Date.now() - startTime };
    } catch (error: any) {
      return { success: false, error: error.message, duration_ms: Date.now() - startTime };
    }
  }
  
  async enableNetworkAdapter(adapterName: string): Promise<PrimitiveResult> {
    const startTime = Date.now();
    try {
      validateShellInput(adapterName, 'adapterName');
      this.logger.info(`Enabling network adapter: ${adapterName}`);
      const output = execSync(`netsh interface set interface "${adapterName}" enabled`, { encoding: 'utf-8' });
      return { success: true, output, duration_ms: Date.now() - startTime };
    } catch (error: any) {
      return { success: false, error: error.message, duration_ms: Date.now() - startTime };
    }
  }
  
  // ========================================
  // UTILITIES
  // ========================================
  
  async sleepPrimitive(milliseconds: number): Promise<PrimitiveResult> {
    const startTime = Date.now();
    await new Promise(resolve => setTimeout(resolve, milliseconds));
    return { success: true, output: `Slept for ${milliseconds}ms`, duration_ms: Date.now() - startTime };
  }
  
  async processExists(processName: string): Promise<boolean> {
    try {
      validateShellInput(processName, 'processName');
      const output = execSync(`tasklist /FI "IMAGENAME eq ${processName}"`, { encoding: 'utf-8' });
      return output.includes(processName);
    } catch { return false; }
  }
  
  async serviceIsRunning(serviceName: string): Promise<boolean> {
    try {
      validateShellInput(serviceName, 'serviceName');
      const output = execSync(`sc query "${serviceName}"`, { encoding: 'utf-8' });
      return output.includes('RUNNING');
    } catch { return false; }
  }
  
  private sleepInternal(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // Registry operations
  async setRegistryValue(key: string, valueName: string, valueData: string, valueType: string = 'REG_SZ'): Promise<PrimitiveResult> {
    const startTime = Date.now();
    try {
      validateShellInput(key, 'registryKey');
      validateShellInput(valueName, 'valueName');
      validateShellInput(valueData, 'valueData');
      validateShellInput(valueType, 'valueType');
      execSync(`reg add "${key}" /v "${valueName}" /t ${valueType} /d "${valueData}" /f`, { timeout: 10000 });
      return {
        success: true,
        duration_ms: Date.now() - startTime
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
        duration_ms: Date.now() - startTime
      };
    }
  }

  async deleteRegistryValue(key: string, valueName: string): Promise<PrimitiveResult> {
    const startTime = Date.now();
    try {
      validateShellInput(key, 'registryKey');
      validateShellInput(valueName, 'valueName');
      execSync(`reg delete "${key}" /v "${valueName}" /f`, { timeout: 10000 });
      return {
        success: true,
        duration_ms: Date.now() - startTime
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
        duration_ms: Date.now() - startTime
      };
    }
  }

  // File operations
  async deleteFile(filePath: string): Promise<PrimitiveResult> {
    const startTime = Date.now();
    try {
      validateShellInput(filePath, 'filePath');
      execSync(`del /f /q "${filePath}"`, { timeout: 10000 });
      return {
        success: true,
        duration_ms: Date.now() - startTime
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
        duration_ms: Date.now() - startTime
      };
    }
  }

  async copyFile(source: string, destination: string): Promise<PrimitiveResult> {
    const startTime = Date.now();
    try {
      validateShellInput(source, 'source');
      validateShellInput(destination, 'destination');
      execSync(`copy /y "${source}" "${destination}"`, { timeout: 10000 });
      return {
        success: true,
        duration_ms: Date.now() - startTime
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
        duration_ms: Date.now() - startTime
      };
    }
  }
}
