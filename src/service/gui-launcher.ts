import { spawnSync, SpawnSyncOptions } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { Logger } from '../common/logger';

/**
 * Execute PowerShell script securely using spawnSync with -EncodedCommand
 */
function securePowerShell(script: string, options: { timeout?: number } = {}): { stdout: string; success: boolean } {
  const encodedCommand = Buffer.from(script, 'utf16le').toString('base64');

  const spawnOptions: SpawnSyncOptions = {
    encoding: 'utf-8',
    timeout: options.timeout || 30000,
    windowsHide: true,
    shell: false  // CRITICAL: Never use shell
  };

  const result = spawnSync('powershell.exe', [
    '-NoProfile',
    '-NonInteractive',
    '-ExecutionPolicy', 'Bypass',
    '-EncodedCommand', encodedCommand
  ], spawnOptions);

  return {
    stdout: (result.stdout as string) || '',
    success: result.status === 0
  };
}

export class GuiLauncher {
  private logger: Logger;
  private agentDir: string;
  private taskName = 'OPSISAgentGUI';

  constructor(logger: Logger, agentDir?: string) {
    this.logger = logger;
    this.agentDir = agentDir || path.join(__dirname, '..', '..');
  }

  public launchGui(): void {
    try {
      // Check if GUI is already running
      if (this.isGuiRunning()) {
        this.logger.info('GUI is already running, skipping launch');
        return;
      }

      const loggedInUser = this.getLoggedInUser();
      if (!loggedInUser) {
        this.logger.warn('No logged-in user found, skipping GUI launch');
        return;
      }

      this.logger.info('Launching GUI for user', { user: loggedInUser });

      const batPath = path.join(this.agentDir, 'start-opsis-gui.bat');

      // Build the PowerShell script - note: values are validated/controlled by agent
      const ps1Content = `
$ErrorActionPreference = 'Stop'
$taskName = '${this.escapeForPowerShell(this.taskName)}'
$batPath = '${this.escapeForPowerShell(batPath)}'
$workDir = '${this.escapeForPowerShell(this.agentDir)}'
$userId = '${this.escapeForPowerShell(loggedInUser)}'

Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

$action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument ('/c "' + $batPath + '"') -WorkingDirectory $workDir
$principal = New-ScheduledTaskPrincipal -UserId $userId -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings | Out-Null
Start-ScheduledTask -TaskName $taskName
`.trim();

      const result = securePowerShell(ps1Content, { timeout: 20000 });

      if (result.success) {
        this.logger.info('GUI launched via scheduled task');
      } else {
        this.logger.warn('GUI launch may have failed');
      }
    } catch (error) {
      this.logger.error('Failed to launch GUI', error);
    }
  }

  public killGui(): void {
    try {
      this.logger.info('Stopping GUI processes');

      // Stop Tauri GUI processes
      securePowerShell('Stop-Process -Name "opsis-agent-gui" -Force -ErrorAction SilentlyContinue', { timeout: 10000 });
    } catch {
      // Ignore errors — process may not be running
    }

    try {
      // Unregister the scheduled task
      const script = `Unregister-ScheduledTask -TaskName '${this.escapeForPowerShell(this.taskName)}' -Confirm:$false -ErrorAction SilentlyContinue`;
      securePowerShell(script, { timeout: 10000 });
    } catch {
      // Ignore cleanup errors
    }

    this.logger.info('GUI processes stopped');
  }

  private isGuiRunning(): boolean {
    try {
      const result = securePowerShell(
        '(Get-Process -Name "opsis-agent-gui" -ErrorAction SilentlyContinue).Count',
        { timeout: 10000 }
      );
      const count = parseInt(result.stdout.trim(), 10);
      return !isNaN(count) && count > 0;
    } catch {
      return false;
    }
  }

  private getLoggedInUser(): string | null {
    try {
      const result = securePowerShell('(Get-CimInstance Win32_ComputerSystem).UserName', { timeout: 10000 });
      const user = result.stdout.trim();
      return user || null;
    } catch {
      return null;
    }
  }

  /**
   * Escape string for safe inclusion in PowerShell single-quoted string
   */
  private escapeForPowerShell(value: string): string {
    // In PowerShell single-quoted strings, only single quotes need escaping (doubled)
    return value.replace(/'/g, "''");
  }
}

export default GuiLauncher;
