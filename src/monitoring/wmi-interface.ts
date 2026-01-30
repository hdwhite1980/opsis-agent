import { execSync } from 'child_process';

export interface ProcessInfo {
  name: string;
  pid: number;
  cpu: number;
  memory_mb: number;
}

export interface ServiceInfo {
  name: string;
  display_name: string;
  state: string;  // "Running" or "Stopped"
  start_type: string;  // "Automatic", "Manual", "Disabled"
}

export interface DiskInfo {
  drive: string;
  total_gb: number;
  used_gb: number;
  free_gb: number;
  used_percent: number;
}

export class WMIInterface {
  
  private executeCommand(command: string): string {
    try {
      const result = execSync(command, {
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'pipe'],
        windowsHide: true
      });
      return result;
    } catch (error: any) {
      throw new Error(`Command failed: ${error.message}`);
    }
  }

  async getCPU(): Promise<number> {
    try {
      const output = this.executeCommand(
        'powershell -Command "Get-Counter -Counter \'\\Processor(_Total)\\% Processor Time\' | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue"'
      );
      return Math.round(parseFloat(output.trim()));
    } catch (error) {
      return 0;
    }
  }

  async getMemory(): Promise<{ total_mb: number; used_mb: number; free_mb: number; used_percent: number }> {
    try {
      const output = this.executeCommand(
        'powershell -Command "Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize, FreePhysicalMemory | ConvertTo-Json"'
      );
      const data = JSON.parse(output);
      const totalMB = Math.round(data.TotalVisibleMemorySize / 1024);
      const freeMB = Math.round(data.FreePhysicalMemory / 1024);
      const usedMB = totalMB - freeMB;
      const usedPercent = Math.round((usedMB / totalMB) * 100);
      
      return { total_mb: totalMB, used_mb: usedMB, free_mb: freeMB, used_percent: usedPercent };
    } catch (error) {
      return { total_mb: 0, used_mb: 0, free_mb: 0, used_percent: 0 };
    }
  }

  async getDisk(): Promise<DiskInfo[]> {
    try {
      const output = this.executeCommand(
        'powershell -Command "Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -ne $null } | Select-Object Name, @{Name=\'TotalGB\';Expression={[math]::Round($_.Used/1GB + $_.Free/1GB, 2)}}, @{Name=\'UsedGB\';Expression={[math]::Round($_.Used/1GB, 2)}}, @{Name=\'FreeGB\';Expression={[math]::Round($_.Free/1GB, 2)}}, @{Name=\'UsedPercent\';Expression={[math]::Round(($_.Used/($_.Used + $_.Free))*100, 0)}} | ConvertTo-Json"'
      );
      
      let data = JSON.parse(output);
      if (!Array.isArray(data)) {
        data = [data];
      }
      
      return data.map((d: any) => ({
        drive: d.Name + ':',
        total_gb: d.TotalGB,
        used_gb: d.UsedGB,
        free_gb: d.FreeGB,
        used_percent: d.UsedPercent
      }));
    } catch (error) {
      return [];
    }
  }

  async getProcesses(): Promise<ProcessInfo[]> {
    try {
      const output = this.executeCommand(
        'powershell -Command "Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Name, Id, CPU, @{Name=\'MemoryMB\';Expression={[math]::Round($_.WorkingSet64/1MB, 2)}} | ConvertTo-Json"'
      );
      
      let data = JSON.parse(output);
      if (!Array.isArray(data)) {
        data = [data];
      }
      
      return data.map((p: any) => ({
        name: p.Name,
        pid: p.Id,
        cpu: Math.round(p.CPU || 0),
        memory_mb: p.MemoryMB
      }));
    } catch (error) {
      return [];
    }
  }

  async getServices(): Promise<ServiceInfo[]> {
    try {
      const output = this.executeCommand(
        'powershell -Command "Get-Service | Select-Object Name, DisplayName, Status, StartType | ConvertTo-Json"'
      );
      
      let data = JSON.parse(output);
      if (!Array.isArray(data)) {
        data = [data];
      }
      
      return data.map((s: any) => {
        // Convert numeric Status codes to strings
        let state: string;
        if (typeof s.Status === 'number') {
          // 1 = Stopped, 4 = Running
          state = s.Status === 1 ? 'Stopped' : s.Status === 4 ? 'Running' : 'Unknown';
        } else {
          state = String(s.Status);
        }
        
        // Convert numeric StartType codes to strings
        let startType: string;
        if (typeof s.StartType === 'number') {
          // 2 = Automatic, 3 = Manual, 4 = Disabled
          if (s.StartType === 2) startType = 'Automatic';
          else if (s.StartType === 3) startType = 'Manual';
          else if (s.StartType === 4) startType = 'Disabled';
          else startType = 'Unknown';
        } else {
          startType = String(s.StartType);
        }
        
        return {
          name: s.Name,
          display_name: s.DisplayName,
          state: state,
          start_type: startType
        };
      });
    } catch (error) {
      return [];
    }
  }
}
