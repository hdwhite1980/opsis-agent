import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { Logger } from '../common/logger';

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
      const loggedInUser = this.getLoggedInUser();
      if (!loggedInUser) {
        this.logger.warn('No logged-in user found, skipping GUI launch');
        return;
      }

      this.logger.info('Launching GUI for user', { user: loggedInUser });

      const batPath = path.join(this.agentDir, 'start-opsis-gui.bat');
      const scriptPath = path.join(this.agentDir, 'data', 'launch-gui.ps1');

      const ps1Content = `
$ErrorActionPreference = 'Stop'
$taskName = '${this.taskName}'
$batPath = '${batPath.replace(/'/g, "''")}'
$workDir = '${this.agentDir.replace(/'/g, "''")}'
$userId = '${loggedInUser.replace(/'/g, "''")}'

Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

$action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument ('/c "' + $batPath + '"') -WorkingDirectory $workDir
$principal = New-ScheduledTaskPrincipal -UserId $userId -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings | Out-Null
Start-ScheduledTask -TaskName $taskName
`.trim();

      fs.writeFileSync(scriptPath, ps1Content, 'utf8');

      execSync(`powershell -NoProfile -ExecutionPolicy Bypass -File "${scriptPath}"`, {
        timeout: 20000,
        windowsHide: true
      });

      // Clean up script file
      try { fs.unlinkSync(scriptPath); } catch { /* ignore */ }

      this.logger.info('GUI launched via scheduled task');
    } catch (error) {
      this.logger.error('Failed to launch GUI', error);
    }
  }

  public killGui(): void {
    try {
      this.logger.info('Stopping GUI processes');

      execSync('powershell -NoProfile -Command "Stop-Process -Name electron -Force -ErrorAction SilentlyContinue"', {
        timeout: 10000,
        windowsHide: true,
        stdio: 'ignore'
      });
    } catch {
      // Ignore errors — process may not be running
    }

    try {
      execSync(
        `powershell -NoProfile -Command "Unregister-ScheduledTask -TaskName '${this.taskName}' -Confirm:$false -ErrorAction SilentlyContinue"`,
        { timeout: 10000, windowsHide: true, stdio: 'ignore' }
      );
    } catch {
      // Ignore cleanup errors
    }

    this.logger.info('GUI processes stopped');
  }

  private getLoggedInUser(): string | null {
    try {
      const output = execSync(
        'powershell -NoProfile -Command "(Get-CimInstance Win32_ComputerSystem).UserName"',
        { timeout: 10000, windowsHide: true, encoding: 'utf8' }
      );
      const user = output.trim();
      return user || null;
    } catch {
      return null;
    }
  }
}

export default GuiLauncher;
