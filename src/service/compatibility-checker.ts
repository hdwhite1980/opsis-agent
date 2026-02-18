import { exec } from 'child_process';
import { promisify } from 'util';
import * as os from 'os';
import { Logger } from '../common/logger';

const execAsync = promisify(exec);

export type CapabilityMode = 'full' | 'limited' | 'monitor-only';

export type CheckStatus = 'green' | 'yellow' | 'red';

export interface CompatibilityCheck {
  name: string;
  status: CheckStatus;
  detail: string;
  impact?: string;
}

export interface CompatibilityReport {
  timestamp: string;
  hostname: string;
  capability_mode: CapabilityMode;
  checks: CompatibilityCheck[];
  disabled_categories: string[];
}

export class CompatibilityChecker {
  private logger: Logger;
  private report: CompatibilityReport | null = null;

  constructor(logger: Logger) {
    this.logger = logger;
  }

  async runFullCheck(): Promise<CompatibilityReport> {
    this.logger.info('Running full compatibility check...');
    const start = Date.now();

    const checks: CompatibilityCheck[] = [];

    const results = await Promise.allSettled([
      this.checkExecutionPolicy(),
      this.checkConstrainedLanguageMode(),
      this.checkEndpointProtection(),
      this.checkScriptBlockLogging(),
      this.checkWDAC(),
      this.checkServiceManagementGPO(),
      this.checkPrivilegeLevel()
    ]);

    for (const result of results) {
      if (result.status === 'fulfilled') {
        checks.push(result.value);
      }
    }

    const capabilityMode = this.determineCapabilityMode(checks);
    const disabledCategories = this.getDisabledCategories(checks);

    this.report = {
      timestamp: new Date().toISOString(),
      hostname: os.hostname(),
      capability_mode: capabilityMode,
      checks,
      disabled_categories: disabledCategories
    };

    const duration = Date.now() - start;
    this.logger.info('Compatibility check complete', {
      capability_mode: capabilityMode,
      checks_count: checks.length,
      red_count: checks.filter(c => c.status === 'red').length,
      yellow_count: checks.filter(c => c.status === 'yellow').length,
      green_count: checks.filter(c => c.status === 'green').length,
      disabled_categories: disabledCategories,
      duration_ms: duration
    });

    return this.report;
  }

  getReport(): CompatibilityReport | null {
    return this.report;
  }

  getCapabilityMode(): CapabilityMode {
    return this.report?.capability_mode || 'full';
  }

  private async checkExecutionPolicy(): Promise<CompatibilityCheck> {
    try {
      const { stdout } = await execAsync(
        'powershell -Command "Get-ExecutionPolicy"',
        { timeout: 10000 }
      );
      const policy = stdout.trim();

      if (policy === 'Restricted') {
        return {
          name: 'PowerShell Execution Policy',
          status: 'red',
          detail: `Policy is ${policy} — scripts cannot run`,
          impact: 'All PowerShell-based remediation disabled'
        };
      }
      if (policy === 'AllSigned') {
        return {
          name: 'PowerShell Execution Policy',
          status: 'yellow',
          detail: `Policy is ${policy} — only signed scripts run`,
          impact: 'Unsigned remediation scripts will fail'
        };
      }
      return {
        name: 'PowerShell Execution Policy',
        status: 'green',
        detail: `Policy is ${policy}`
      };
    } catch {
      return {
        name: 'PowerShell Execution Policy',
        status: 'red',
        detail: 'Cannot determine execution policy — PowerShell may be unavailable',
        impact: 'All PowerShell-based operations disabled'
      };
    }
  }

  private async checkConstrainedLanguageMode(): Promise<CompatibilityCheck> {
    try {
      const { stdout } = await execAsync(
        'powershell -Command "$ExecutionContext.SessionState.LanguageMode"',
        { timeout: 10000 }
      );
      const mode = stdout.trim();

      if (mode === 'ConstrainedLanguage') {
        return {
          name: 'Constrained Language Mode',
          status: 'red',
          detail: 'PowerShell is in Constrained Language Mode (AppLocker/WDAC enforced)',
          impact: 'Add-Type, New-Object, and most .NET calls blocked — service management, process manipulation, and registry operations severely limited'
        };
      }
      if (mode === 'RestrictedLanguage') {
        return {
          name: 'Constrained Language Mode',
          status: 'red',
          detail: 'PowerShell is in Restricted Language Mode',
          impact: 'Most remediation primitives will fail'
        };
      }
      return {
        name: 'Constrained Language Mode',
        status: 'green',
        detail: `Language mode: ${mode}`
      };
    } catch {
      return {
        name: 'Constrained Language Mode',
        status: 'yellow',
        detail: 'Cannot determine language mode',
        impact: 'Some operations may fail unexpectedly'
      };
    }
  }

  private async checkEndpointProtection(): Promise<CompatibilityCheck> {
    try {
      // Attempt a harmless PowerShell command from the service context
      const { stdout } = await execAsync(
        'powershell -Command "Get-Process -Name explorer -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Name"',
        { timeout: 15000 }
      );
      const result = stdout.trim();

      if (result.toLowerCase() === 'explorer') {
        return {
          name: 'Endpoint Protection Interference',
          status: 'green',
          detail: 'PowerShell execution from service context works normally'
        };
      }

      // Explorer may not be running (server/headless), still counts as success if no error
      return {
        name: 'Endpoint Protection Interference',
        status: 'green',
        detail: 'PowerShell execution from service context permitted'
      };
    } catch (error: any) {
      const errStr = String(error);
      if (errStr.includes('Access') || errStr.includes('denied') || errStr.includes('blocked')) {
        return {
          name: 'Endpoint Protection Interference',
          status: 'red',
          detail: 'PowerShell execution blocked — likely EDR (CrowdStrike, SentinelOne, etc.)',
          impact: 'All PowerShell-based remediation blocked. Add OPSIS agent to EDR exclusions.'
        };
      }
      if (errStr.includes('timeout') || errStr.includes('ETIMEDOUT')) {
        return {
          name: 'Endpoint Protection Interference',
          status: 'red',
          detail: 'PowerShell execution timed out — likely EDR blocking or sandboxing',
          impact: 'Remediation commands will time out. Add OPSIS agent to EDR exclusions.'
        };
      }
      return {
        name: 'Endpoint Protection Interference',
        status: 'yellow',
        detail: `PowerShell test returned error: ${errStr.substring(0, 200)}`,
        impact: 'Some remediation operations may be blocked'
      };
    }
  }

  private async checkScriptBlockLogging(): Promise<CompatibilityCheck> {
    try {
      const { stdout } = await execAsync(
        'powershell -Command "try { $k = Get-ItemProperty -Path \'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\' -ErrorAction SilentlyContinue; if ($k.EnableScriptBlockLogging -eq 1) { \'Enabled\' } else { \'Disabled\' } } catch { \'Disabled\' }"',
        { timeout: 10000 }
      );
      const enabled = stdout.trim() === 'Enabled';

      if (enabled) {
        return {
          name: 'Script Block Logging',
          status: 'yellow',
          detail: 'Script Block Logging is enabled via GPO — all agent PowerShell commands are logged to event log',
          impact: 'Event log fills faster. Agent event monitor should filter OPSIS-generated events.'
        };
      }
      return {
        name: 'Script Block Logging',
        status: 'green',
        detail: 'Script Block Logging is not enabled'
      };
    } catch {
      return {
        name: 'Script Block Logging',
        status: 'green',
        detail: 'Cannot determine Script Block Logging status (likely disabled)'
      };
    }
  }

  private async checkWDAC(): Promise<CompatibilityCheck> {
    try {
      const { stdout } = await execAsync(
        'powershell -Command "try { $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard -ErrorAction SilentlyContinue; if ($dg.CodeIntegrityPolicyEnforcementStatus -eq 2) { \'Enforced\' } elseif ($dg.CodeIntegrityPolicyEnforcementStatus -eq 1) { \'Audit\' } else { \'Off\' } } catch { \'Unknown\' }"',
        { timeout: 15000 }
      );
      const status = stdout.trim();

      if (status === 'Enforced') {
        return {
          name: 'Windows Defender Application Control',
          status: 'red',
          detail: 'WDAC is enforced — only signed/whitelisted binaries and scripts can run',
          impact: 'Agent PowerShell commands will be blocked unless OPSIS is whitelisted in WDAC policy'
        };
      }
      if (status === 'Audit') {
        return {
          name: 'Windows Defender Application Control',
          status: 'yellow',
          detail: 'WDAC is in audit mode — violations are logged but not blocked',
          impact: 'Operations work but generate audit events. Consider whitelisting OPSIS before enforcement.'
        };
      }
      return {
        name: 'Windows Defender Application Control',
        status: 'green',
        detail: 'WDAC is not enforced'
      };
    } catch {
      return {
        name: 'Windows Defender Application Control',
        status: 'green',
        detail: 'WDAC/Device Guard not available on this system'
      };
    }
  }

  private async checkServiceManagementGPO(): Promise<CompatibilityCheck> {
    try {
      const { stdout } = await execAsync(
        'powershell -Command "try { Get-Service -Name Spooler -ErrorAction Stop | Select-Object -ExpandProperty Status } catch { $_.Exception.Message }"',
        { timeout: 10000 }
      );
      const result = stdout.trim();

      if (result.includes('Access') && result.includes('denied')) {
        return {
          name: 'Service Management GPO',
          status: 'red',
          detail: 'Access denied when querying services — GPO restricts service management for this account',
          impact: 'Service restart/stop remediation will fail'
        };
      }
      return {
        name: 'Service Management GPO',
        status: 'green',
        detail: `Service query permitted (Spooler status: ${result})`
      };
    } catch (error: any) {
      const errStr = String(error);
      if (errStr.includes('Access') || errStr.includes('denied')) {
        return {
          name: 'Service Management GPO',
          status: 'red',
          detail: 'GPO restricts service management from this context',
          impact: 'Service restart/stop remediation will fail'
        };
      }
      return {
        name: 'Service Management GPO',
        status: 'yellow',
        detail: 'Could not verify service management permissions'
      };
    }
  }

  private async checkPrivilegeLevel(): Promise<CompatibilityCheck> {
    try {
      const { stdout } = await execAsync(
        'powershell -Command "[System.Security.Principal.WindowsIdentity]::GetCurrent().Name"',
        { timeout: 10000 }
      );
      const identity = stdout.trim();

      if (identity.includes('SYSTEM')) {
        return {
          name: 'Privilege Level',
          status: 'green',
          detail: `Running as ${identity} (full privileges)`
        };
      }
      if (identity.includes('Administrator')) {
        return {
          name: 'Privilege Level',
          status: 'green',
          detail: `Running as ${identity} (elevated)`
        };
      }
      return {
        name: 'Privilege Level',
        status: 'yellow',
        detail: `Running as ${identity} — not SYSTEM or Administrator`,
        impact: 'Some operations requiring elevated privileges may fail'
      };
    } catch {
      return {
        name: 'Privilege Level',
        status: 'yellow',
        detail: 'Cannot determine service identity'
      };
    }
  }

  private determineCapabilityMode(checks: CompatibilityCheck[]): CapabilityMode {
    const redChecks = checks.filter(c => c.status === 'red');
    const redNames = redChecks.map(c => c.name);
    const greenNames = checks.filter(c => c.status === 'green').map(c => c.name);

    // If the functional PowerShell test passed, OPSIS can actually execute scripts
    // even if WDAC is enforced (means OPSIS is whitelisted in the WDAC policy).
    const psWorksInPractice = greenNames.includes('Endpoint Protection Interference');

    // Monitor-only: PowerShell completely blocked or WDAC enforced + CLM
    const psBlocked = redNames.includes('PowerShell Execution Policy') ||
                      redNames.includes('Endpoint Protection Interference');
    const wdacAndClm = redNames.includes('Windows Defender Application Control') &&
                       redNames.includes('Constrained Language Mode');

    if (psBlocked || wdacAndClm) {
      return 'monitor-only';
    }

    // If WDAC is enforced but the functional test proves PowerShell works,
    // OPSIS is whitelisted — don't downgrade to limited mode for WDAC alone.
    const wdacEffective = redNames.includes('Windows Defender Application Control') && !psWorksInPractice;

    // Limited: CLM or effective WDAC block or service GPO restrictions
    if (redNames.includes('Constrained Language Mode') ||
        wdacEffective ||
        redNames.includes('Service Management GPO')) {
      return 'limited';
    }

    return 'full';
  }

  private getDisabledCategories(checks: CompatibilityCheck[]): string[] {
    const disabled: string[] = [];
    const redNames = checks.filter(c => c.status === 'red').map(c => c.name);
    const greenNames = checks.filter(c => c.status === 'green').map(c => c.name);
    const psWorksInPractice = greenNames.includes('Endpoint Protection Interference');

    if (redNames.includes('Constrained Language Mode')) {
      disabled.push('registry-modification', 'advanced-process-management', 'wmi-operations');
    }
    if (redNames.includes('Service Management GPO')) {
      disabled.push('service-restart', 'service-stop');
    }
    // Only disable script/binary execution for WDAC if the functional test also failed
    // (if PowerShell works in practice, OPSIS is whitelisted in the WDAC policy)
    if (redNames.includes('Windows Defender Application Control') && !psWorksInPractice) {
      disabled.push('script-execution', 'binary-execution');
    }
    if (redNames.includes('Endpoint Protection Interference')) {
      disabled.push('powershell-remediation');
    }
    if (redNames.includes('PowerShell Execution Policy')) {
      disabled.push('powershell-remediation');
    }

    return [...new Set(disabled)];
  }
}
