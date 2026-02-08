import { spawnSync, SpawnSyncOptions } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import Logger from '../../common/logger';

// ===========================================
// ERROR SANITIZATION (SECURITY)
// ===========================================

// Patterns that indicate sensitive information in error messages
const SENSITIVE_PATTERNS = [
  /password/gi,
  /secret/gi,
  /token/gi,
  /credential/gi,
  /key\s*=/gi,
  /api[-_]?key/gi,
  /bearer/gi,
  /authorization/gi,
  /[a-zA-Z0-9+/]{40,}/g,  // Base64-like strings
  /\b[\w.-]+@[\w.-]+\.\w+\b/g,  // Email addresses
  /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,  // IP addresses (internal info)
];

// Known safe error prefixes that can be passed through
const SAFE_ERROR_PREFIXES = [
  'Cannot kill protected process',
  'Cannot stop protected service',
  'Cannot restart protected service',
  'Invalid',
  'Rate limit exceeded',
  'Process not found',
  'Service not found',
  'File not found',
  'Access denied',
  'Permission denied',
  'Operation timed out',
  'Path outside allowed directories',
];

/**
 * Sanitize error messages to prevent information leakage
 * Returns a safe generic message if the error might contain sensitive data
 */
function sanitizeErrorMessage(error: string | undefined, context: string): string {
  if (!error) {
    return `${context} failed`;
  }

  // Check if error starts with a known safe prefix
  const isSafePrefix = SAFE_ERROR_PREFIXES.some(prefix =>
    error.toLowerCase().startsWith(prefix.toLowerCase())
  );

  if (isSafePrefix) {
    // Still strip any sensitive patterns even from "safe" errors
    let sanitized = error;
    for (const pattern of SENSITIVE_PATTERNS) {
      sanitized = sanitized.replace(pattern, '[REDACTED]');
    }
    return sanitized;
  }

  // Check for sensitive patterns
  for (const pattern of SENSITIVE_PATTERNS) {
    if (pattern.test(error)) {
      return `${context} failed: operation error (details redacted)`;
    }
  }

  // Limit error message length to prevent data exfiltration
  if (error.length > 200) {
    return `${context} failed: ${error.substring(0, 100)}... (truncated)`;
  }

  // Error appears safe
  return error;
}

export interface PrimitiveResult {
  success: boolean;
  output?: string;
  error?: string;
  duration_ms: number;
}

// ===========================================
// DIAGNOSTIC RESULT INTERFACE
// ===========================================

export interface DiagnosticResult<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  duration_ms: number;
  collected_at: string;
}

// Diagnostic data types
export interface ProcessInfo {
  name: string;
  pid: number;
  cpu_percent: number;
  memory_mb: number;
  thread_count: number;
  handle_count: number;
  start_time?: string;
}

export interface ProcessorInfo {
  name: string;
  load_percent: number;
  max_clock_mhz: number;
  current_clock_mhz: number;
  cores: number;
  logical_processors: number;
}

export interface InstalledProgram {
  name: string;
  version: string;
  install_date: string;
  publisher?: string;
}

export interface ServiceInfo {
  name: string;
  display_name: string;
  status: string;
  start_type: string;
  account: string;
  path_to_executable?: string;
  dependencies: string[];
  dependents: string[];
}

export interface ServiceEvent {
  timestamp: string;
  level: string;
  event_id: number;
  message: string;
}

export interface DiskUsageInfo {
  drive: string;
  label?: string;
  file_system: string;
  total_gb: number;
  used_gb: number;
  free_gb: number;
  percent_free: number;
}

export interface FolderSize {
  path: string;
  size_gb: number;
  file_count?: number;
}

export interface FileGrowth {
  path: string;
  growth_mb: number;
  largest_new_files: Array<{ name: string; size_mb: number; created: string }>;
}

export interface SMARTData {
  drive: string;
  model: string;
  serial?: string;
  health_status: string;
  temperature_celsius?: number;
  power_on_hours?: number;
}

export interface MemoryConsumer {
  name: string;
  pid: number;
  working_set_mb: number;
  private_bytes_mb: number;
  handle_count: number;
}

export interface PageFileStatus {
  location: string;
  allocated_mb: number;
  used_mb: number;
  peak_mb: number;
  percent_used: number;
}

export interface SystemMemoryInfo {
  total_mb: number;
  available_mb: number;
  committed_mb: number;
  cached_mb: number;
  percent_used: number;
}

export interface NetworkAdapterInfo {
  name: string;
  description: string;
  status: string;
  link_speed_mbps?: number;
  ip_addresses: string[];
  mac_address: string;
  dhcp_enabled: boolean;
  dns_servers: string[];
  default_gateway?: string;
}

export interface DNSTestResult {
  host: string;
  resolved: boolean;
  ip_addresses?: string[];
  response_time_ms?: number;
  error?: string;
}

export interface RouteEntry {
  destination: string;
  netmask: string;
  gateway: string;
  interface_addr: string;
  metric: number;
}

export interface ConnectivityTestResult {
  endpoint: string;
  reachable: boolean;
  response_time_ms?: number;
  status_code?: number;
  error?: string;
}

export interface SystemSnapshot {
  hostname: string;
  os_version: string;
  os_build: string;
  uptime_hours: number;
  last_boot: string;
  pending_reboot: boolean;
  pending_reboot_reasons?: string[];
  running_services_count: number;
  stopped_auto_services_count: number;
}

export interface EventLogError {
  log_name: string;
  source: string;
  event_id: number;
  level: string;
  timestamp: string;
  message: string;
}

// ===========================================
// SECURE INPUT VALIDATION
// ===========================================

// Strict whitelist validation for identifiers (process names, service names)
function validateIdentifier(input: string, label: string): void {
  if (!input || typeof input !== 'string') {
    throw new Error(`Invalid ${label}: must be a non-empty string`);
  }
  // Only allow alphanumeric, hyphen, underscore, period, space
  if (!/^[a-zA-Z0-9\-_. ]+$/.test(input)) {
    throw new Error(`Invalid ${label}: contains disallowed characters`);
  }
  if (input.length > 260) {
    throw new Error(`Invalid ${label}: exceeds maximum length`);
  }
}

// Strict validation for file paths - prevents traversal and injection
function validateFilePath(inputPath: string, label: string, allowedBaseDirs?: string[]): string {
  if (!inputPath || typeof inputPath !== 'string') {
    throw new Error(`Invalid ${label}: must be a non-empty string`);
  }

  // Normalize the path to resolve .. and .
  const normalizedPath = path.resolve(inputPath);

  // Check for null bytes (path injection)
  if (inputPath.includes('\0')) {
    throw new Error(`Invalid ${label}: contains null bytes`);
  }

  // If allowed base directories specified, verify path is within them
  if (allowedBaseDirs && allowedBaseDirs.length > 0) {
    const isAllowed = allowedBaseDirs.some(baseDir => {
      const normalizedBase = path.resolve(baseDir);
      return normalizedPath.startsWith(normalizedBase + path.sep) || normalizedPath === normalizedBase;
    });
    if (!isAllowed) {
      throw new Error(`Invalid ${label}: path outside allowed directories`);
    }
  }

  // Check path length
  if (normalizedPath.length > 260) {
    throw new Error(`Invalid ${label}: path exceeds maximum length`);
  }

  return normalizedPath;
}

// Validate registry key format
function validateRegistryKey(key: string): void {
  if (!key || typeof key !== 'string') {
    throw new Error('Invalid registry key: must be a non-empty string');
  }
  // Registry keys must start with valid hive
  const validHives = ['HKLM', 'HKCU', 'HKCR', 'HKU', 'HKCC',
                      'HKEY_LOCAL_MACHINE', 'HKEY_CURRENT_USER',
                      'HKEY_CLASSES_ROOT', 'HKEY_USERS', 'HKEY_CURRENT_CONFIG'];
  const startsWithHive = validHives.some(hive =>
    key.toUpperCase().startsWith(hive + '\\') || key.toUpperCase() === hive
  );
  if (!startsWithHive) {
    throw new Error('Invalid registry key: must start with valid hive');
  }
  // Only allow safe characters in registry path
  if (!/^[a-zA-Z0-9\\_\-. ]+$/.test(key)) {
    throw new Error('Invalid registry key: contains disallowed characters');
  }
}

// Validate registry value type
function validateRegistryType(valueType: string): void {
  const validTypes = ['REG_SZ', 'REG_EXPAND_SZ', 'REG_DWORD', 'REG_QWORD', 'REG_BINARY', 'REG_MULTI_SZ'];
  if (!validTypes.includes(valueType.toUpperCase())) {
    throw new Error(`Invalid registry type: must be one of ${validTypes.join(', ')}`);
  }
}

// Validate network adapter name
function validateAdapterName(name: string): void {
  if (!name || typeof name !== 'string') {
    throw new Error('Invalid adapter name: must be a non-empty string');
  }
  // Adapter names are fairly permissive but no control chars or quotes
  if (/[\x00-\x1f"<>|]/.test(name)) {
    throw new Error('Invalid adapter name: contains disallowed characters');
  }
  if (name.length > 256) {
    throw new Error('Invalid adapter name: exceeds maximum length');
  }
}

// Check if path is a symlink (prevent symlink attacks)
function isSymlink(filePath: string): boolean {
  try {
    const stats = fs.lstatSync(filePath);
    return stats.isSymbolicLink();
  } catch {
    return false;
  }
}

// ===========================================
// SECURE COMMAND EXECUTION
// ===========================================

interface SecureExecOptions {
  timeout?: number;
  cwd?: string;
}

// Execute command securely using spawn with array arguments (no shell)
function secureExec(command: string, args: string[], options: SecureExecOptions = {}): { stdout: string; stderr: string; success: boolean } {
  const spawnOptions: SpawnSyncOptions = {
    encoding: 'utf-8',
    timeout: options.timeout || 30000,
    cwd: options.cwd,
    shell: false,  // CRITICAL: Never use shell
    windowsHide: true
  };

  const result = spawnSync(command, args, spawnOptions);

  return {
    stdout: (result.stdout as string) || '',
    stderr: (result.stderr as string) || '',
    success: result.status === 0
  };
}

// Execute PowerShell command securely
function securePowerShell(script: string, options: SecureExecOptions = {}): { stdout: string; stderr: string; success: boolean } {
  // Use -NoProfile -NonInteractive for security
  // -EncodedCommand with Base64 prevents injection
  const encodedCommand = Buffer.from(script, 'utf16le').toString('base64');

  return secureExec('powershell.exe', [
    '-NoProfile',
    '-NonInteractive',
    '-ExecutionPolicy', 'Bypass',
    '-EncodedCommand', encodedCommand
  ], options);
}

// ===========================================
// PROTECTED RESOURCES
// ===========================================

// Protected processes that must NEVER be killed
const PROTECTED_PROCESSES = new Set([
  'svchost.exe', 'lsass.exe', 'csrss.exe', 'winlogon.exe',
  'dwm.exe', 'explorer.exe', 'services.exe', 'smss.exe',
  'wininit.exe', 'system', 'system idle process',
  'conhost.exe', 'ntoskrnl.exe', 'spoolsv.exe', 'wuauserv.exe',
  'taskhostw.exe', 'sihost.exe', 'fontdrvhost.exe', 'audiodg.exe'
]);

const PROTECTED_SERVICES = new Set([
  'rpcss', 'dcomlaunch', 'lsm', 'samss', 'eventlog',
  'plugplay', 'power', 'winmgmt', 'cryptsvc', 'bits',
  'lanmanserver', 'lanmanworkstation', 'schedule', 'w32time',
  'dnscache', 'dhcp', 'netlogon', 'wuauserv', 'trustedinstaller'
]);

// Directories where file operations are allowed
const ALLOWED_FILE_DIRS = [
  process.env.TEMP || 'C:\\Windows\\Temp',
  process.env.TMP || 'C:\\Windows\\Temp',
  'C:\\Windows\\SoftwareDistribution',
  'C:\\$Recycle.Bin'
];

// ===========================================
// RATE LIMITING
// ===========================================

interface RateLimitEntry {
  count: number;
  resetTime: number;
}

const rateLimits: Map<string, RateLimitEntry> = new Map();
const RATE_LIMIT_WINDOW = 60000; // 1 minute
const RATE_LIMITS: Record<string, number> = {
  'killProcess': 10,
  'restartService': 5,
  'cleanTempFiles': 2,
  'emptyRecycleBin': 2,
  'clearWindowsUpdateCache': 1,
  'flushDNS': 10,
  'networkAdapter': 5,
  'registry': 20,
  'fileOps': 50
};

function checkRateLimit(operation: string): void {
  const now = Date.now();
  const limit = RATE_LIMITS[operation] || 100;

  let entry = rateLimits.get(operation);
  if (!entry || now > entry.resetTime) {
    entry = { count: 0, resetTime: now + RATE_LIMIT_WINDOW };
    rateLimits.set(operation, entry);
  }

  entry.count++;
  if (entry.count > limit) {
    throw new Error(`Rate limit exceeded for ${operation}: max ${limit} per minute`);
  }
}

// ===========================================
// PRIMITIVES CLASS
// ===========================================

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
      checkRateLimit('killProcess');
      validateIdentifier(processName, 'processName');

      if (PROTECTED_PROCESSES.has(processName.toLowerCase())) {
        return { success: false, error: `Cannot kill protected process: ${processName}`, duration_ms: Date.now() - startTime };
      }

      this.logger.info(`Killing process: ${processName}`);

      // Use taskkill with array arguments - no shell injection possible
      const result = secureExec('taskkill.exe', ['/F', '/IM', processName, '/T'], { timeout: 10000 });

      if (result.success) {
        return { success: true, output: result.stdout, duration_ms: Date.now() - startTime };
      } else {
        return { success: false, error: sanitizeErrorMessage(result.stderr, 'Kill process'), duration_ms: Date.now() - startTime };
      }
    } catch (error: any) {
      return { success: false, error: sanitizeErrorMessage(error.message, 'Kill process'), duration_ms: Date.now() - startTime };
    }
  }

  async killProcessByPID(pid: number): Promise<PrimitiveResult> {
    const startTime = Date.now();
    try {
      checkRateLimit('killProcess');

      // Validate PID is a positive integer
      if (!Number.isInteger(pid) || pid <= 0 || pid > 4194304) {
        throw new Error('Invalid PID: must be a positive integer');
      }

      this.logger.info(`Killing process PID: ${pid}`);

      const result = secureExec('taskkill.exe', ['/F', '/PID', pid.toString(), '/T'], { timeout: 10000 });

      if (result.success) {
        return { success: true, output: result.stdout, duration_ms: Date.now() - startTime };
      } else {
        return { success: false, error: sanitizeErrorMessage(result.stderr, 'Kill process by PID'), duration_ms: Date.now() - startTime };
      }
    } catch (error: any) {
      return { success: false, error: sanitizeErrorMessage(error.message, 'Kill process by PID'), duration_ms: Date.now() - startTime };
    }
  }

  async startProcess(processPath: string, args?: string): Promise<PrimitiveResult> {
    const startTime = Date.now();
    try {
      checkRateLimit('killProcess');

      // Validate and normalize path
      const normalizedPath = validateFilePath(processPath, 'processPath');

      // Verify file exists and is executable
      if (!fs.existsSync(normalizedPath)) {
        throw new Error('Process executable not found');
      }

      // Check for symlink attack
      if (isSymlink(normalizedPath)) {
        throw new Error('Cannot execute symlinks');
      }

      this.logger.info(`Starting process: ${normalizedPath}`);

      // Parse args safely if provided
      const argArray: string[] = [];
      if (args) {
        // Simple space-split - for complex args, should use proper parsing
        validateIdentifier(args, 'args');
        argArray.push(...args.split(' ').filter(a => a.length > 0));
      }

      // Use spawn directly - no shell
      const result = secureExec(normalizedPath, argArray, { timeout: 5000 });

      return { success: true, output: 'Process started', duration_ms: Date.now() - startTime };
    } catch (error: any) {
      return { success: false, error: sanitizeErrorMessage(error.message, 'Start process'), duration_ms: Date.now() - startTime };
    }
  }

  // ========================================
  // SERVICE MANAGEMENT
  // ========================================

  async restartService(serviceName: string): Promise<PrimitiveResult> {
    const startTime = Date.now();
    try {
      checkRateLimit('restartService');
      validateIdentifier(serviceName, 'serviceName');

      if (PROTECTED_SERVICES.has(serviceName.toLowerCase())) {
        return { success: false, error: `Cannot restart protected service: ${serviceName}`, duration_ms: Date.now() - startTime };
      }

      this.logger.info(`Restarting service: ${serviceName}`);

      // Stop service using sc.exe with array args
      secureExec('sc.exe', ['stop', serviceName], { timeout: 30000 });

      await this.sleepInternal(2000);

      // Start service
      const result = secureExec('sc.exe', ['start', serviceName], { timeout: 30000 });

      if (result.success || result.stdout.includes('RUNNING')) {
        return { success: true, output: result.stdout, duration_ms: Date.now() - startTime };
      } else {
        return { success: false, error: sanitizeErrorMessage(result.stderr, 'Restart service'), duration_ms: Date.now() - startTime };
      }
    } catch (error: any) {
      return { success: false, error: sanitizeErrorMessage(error.message, 'Restart service'), duration_ms: Date.now() - startTime };
    }
  }

  async startService(serviceName: string): Promise<PrimitiveResult> {
    const startTime = Date.now();
    try {
      checkRateLimit('restartService');
      validateIdentifier(serviceName, 'serviceName');

      this.logger.info(`Starting service: ${serviceName}`);

      const result = secureExec('sc.exe', ['start', serviceName], { timeout: 30000 });

      if (result.success || result.stdout.includes('RUNNING') || result.stdout.includes('START_PENDING')) {
        return { success: true, output: result.stdout, duration_ms: Date.now() - startTime };
      } else {
        return { success: false, error: sanitizeErrorMessage(result.stderr, 'Start service'), duration_ms: Date.now() - startTime };
      }
    } catch (error: any) {
      return { success: false, error: sanitizeErrorMessage(error.message, 'Start service'), duration_ms: Date.now() - startTime };
    }
  }

  async stopService(serviceName: string): Promise<PrimitiveResult> {
    const startTime = Date.now();
    try {
      checkRateLimit('restartService');
      validateIdentifier(serviceName, 'serviceName');

      if (PROTECTED_SERVICES.has(serviceName.toLowerCase())) {
        return { success: false, error: `Cannot stop protected service: ${serviceName}`, duration_ms: Date.now() - startTime };
      }

      this.logger.info(`Stopping service: ${serviceName}`);

      const result = secureExec('sc.exe', ['stop', serviceName], { timeout: 30000 });

      if (result.success || result.stdout.includes('STOPPED') || result.stdout.includes('STOP_PENDING')) {
        return { success: true, output: result.stdout, duration_ms: Date.now() - startTime };
      } else {
        return { success: false, error: sanitizeErrorMessage(result.stderr, 'Stop service'), duration_ms: Date.now() - startTime };
      }
    } catch (error: any) {
      return { success: false, error: sanitizeErrorMessage(error.message, 'Stop service'), duration_ms: Date.now() - startTime };
    }
  }

  // ========================================
  // DISK MANAGEMENT
  // ========================================

  async cleanTempFiles(): Promise<PrimitiveResult> {
    const startTime = Date.now();
    try {
      checkRateLimit('cleanTempFiles');

      this.logger.info('Cleaning temp files');

      // Use PowerShell with proper encoding to avoid injection
      const script = `
        $ErrorActionPreference = 'SilentlyContinue'
        $tempPaths = @($env:TEMP, $env:TMP, 'C:\\Windows\\Temp')
        $deleted = 0
        foreach ($tempPath in $tempPaths) {
          if (Test-Path $tempPath) {
            $files = Get-ChildItem -Path $tempPath -File -Recurse
            foreach ($file in $files) {
              try {
                Remove-Item -Path $file.FullName -Force
                $deleted++
              } catch {}
            }
          }
        }
        Write-Output "Deleted $deleted temp files"
      `;

      const result = securePowerShell(script, { timeout: 300000 });

      return { success: true, output: result.stdout || 'Temp files cleaned', duration_ms: Date.now() - startTime };
    } catch (error: any) {
      return { success: false, error: sanitizeErrorMessage(error.message, 'Clean temp files'), duration_ms: Date.now() - startTime };
    }
  }

  async emptyRecycleBin(): Promise<PrimitiveResult> {
    const startTime = Date.now();
    try {
      checkRateLimit('emptyRecycleBin');

      this.logger.info('Emptying recycle bin');

      const script = `
        $ErrorActionPreference = 'SilentlyContinue'
        Clear-RecycleBin -Force -Confirm:$false
        Write-Output 'Recycle bin emptied'
      `;

      const result = securePowerShell(script, { timeout: 60000 });

      return { success: true, output: result.stdout || 'Recycle bin emptied', duration_ms: Date.now() - startTime };
    } catch (error: any) {
      return { success: false, error: sanitizeErrorMessage(error.message, 'Empty recycle bin'), duration_ms: Date.now() - startTime };
    }
  }

  async clearWindowsUpdateCache(): Promise<PrimitiveResult> {
    const startTime = Date.now();
    try {
      checkRateLimit('clearWindowsUpdateCache');

      this.logger.info('Clearing Windows Update cache');

      const script = `
        $ErrorActionPreference = 'SilentlyContinue'
        Stop-Service -Name wuauserv -Force
        Start-Sleep -Seconds 2
        Remove-Item -Path 'C:\\Windows\\SoftwareDistribution\\Download\\*' -Recurse -Force
        Start-Service -Name wuauserv
        Write-Output 'Windows Update cache cleared'
      `;

      const result = securePowerShell(script, { timeout: 120000 });

      return { success: true, output: result.stdout || 'Windows Update cache cleared', duration_ms: Date.now() - startTime };
    } catch (error: any) {
      return { success: false, error: sanitizeErrorMessage(error.message, 'Clear Windows Update cache'), duration_ms: Date.now() - startTime };
    }
  }

  // ========================================
  // NETWORK OPERATIONS
  // ========================================

  async flushDNS(): Promise<PrimitiveResult> {
    const startTime = Date.now();
    try {
      checkRateLimit('flushDNS');

      this.logger.info('Flushing DNS cache');

      const result = secureExec('ipconfig.exe', ['/flushdns'], { timeout: 10000 });

      return { success: true, output: result.stdout, duration_ms: Date.now() - startTime };
    } catch (error: any) {
      return { success: false, error: sanitizeErrorMessage(error.message, 'Flush DNS'), duration_ms: Date.now() - startTime };
    }
  }

  async releaseIP(): Promise<PrimitiveResult> {
    const startTime = Date.now();
    try {
      checkRateLimit('flushDNS');

      this.logger.info('Releasing IP address');

      const result = secureExec('ipconfig.exe', ['/release'], { timeout: 30000 });

      return { success: true, output: result.stdout, duration_ms: Date.now() - startTime };
    } catch (error: any) {
      return { success: false, error: sanitizeErrorMessage(error.message, 'Release IP'), duration_ms: Date.now() - startTime };
    }
  }

  async renewIP(): Promise<PrimitiveResult> {
    const startTime = Date.now();
    try {
      checkRateLimit('flushDNS');

      this.logger.info('Renewing IP address');

      const result = secureExec('ipconfig.exe', ['/renew'], { timeout: 60000 });

      return { success: true, output: result.stdout, duration_ms: Date.now() - startTime };
    } catch (error: any) {
      return { success: false, error: sanitizeErrorMessage(error.message, 'Renew IP'), duration_ms: Date.now() - startTime };
    }
  }

  async disableNetworkAdapter(adapterName: string): Promise<PrimitiveResult> {
    const startTime = Date.now();
    try {
      checkRateLimit('networkAdapter');
      validateAdapterName(adapterName);

      this.logger.info(`Disabling network adapter: ${adapterName}`);

      const script = `Disable-NetAdapter -Name '${adapterName.replace(/'/g, "''")}' -Confirm:$false`;
      const result = securePowerShell(script, { timeout: 30000 });

      return { success: result.success, output: result.stdout, error: sanitizeErrorMessage(result.stderr, 'Disable network adapter'), duration_ms: Date.now() - startTime };
    } catch (error: any) {
      return { success: false, error: sanitizeErrorMessage(error.message, 'Disable network adapter'), duration_ms: Date.now() - startTime };
    }
  }

  async enableNetworkAdapter(adapterName: string): Promise<PrimitiveResult> {
    const startTime = Date.now();
    try {
      checkRateLimit('networkAdapter');
      validateAdapterName(adapterName);

      this.logger.info(`Enabling network adapter: ${adapterName}`);

      const script = `Enable-NetAdapter -Name '${adapterName.replace(/'/g, "''")}' -Confirm:$false`;
      const result = securePowerShell(script, { timeout: 30000 });

      return { success: result.success, output: result.stdout, error: sanitizeErrorMessage(result.stderr, 'Enable network adapter'), duration_ms: Date.now() - startTime };
    } catch (error: any) {
      return { success: false, error: sanitizeErrorMessage(error.message, 'Enable network adapter'), duration_ms: Date.now() - startTime };
    }
  }

  // ========================================
  // UTILITIES
  // ========================================

  async sleepPrimitive(milliseconds: number): Promise<PrimitiveResult> {
    const startTime = Date.now();

    // Validate milliseconds
    if (!Number.isInteger(milliseconds) || milliseconds < 0 || milliseconds > 300000) {
      return { success: false, error: 'Invalid sleep duration: must be 0-300000ms', duration_ms: 0 };
    }

    await new Promise(resolve => setTimeout(resolve, milliseconds));
    return { success: true, output: `Slept for ${milliseconds}ms`, duration_ms: Date.now() - startTime };
  }

  async processExists(processName: string): Promise<boolean> {
    try {
      validateIdentifier(processName, 'processName');

      const result = secureExec('tasklist.exe', ['/FI', `IMAGENAME eq ${processName}`, '/NH'], { timeout: 10000 });
      return result.stdout.toLowerCase().includes(processName.toLowerCase());
    } catch {
      return false;
    }
  }

  async serviceIsRunning(serviceName: string): Promise<boolean> {
    try {
      validateIdentifier(serviceName, 'serviceName');

      const result = secureExec('sc.exe', ['query', serviceName], { timeout: 10000 });
      return result.stdout.includes('RUNNING');
    } catch {
      return false;
    }
  }

  private sleepInternal(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // ========================================
  // REGISTRY OPERATIONS
  // ========================================

  async setRegistryValue(key: string, valueName: string, valueData: string, valueType: string = 'REG_SZ'): Promise<PrimitiveResult> {
    const startTime = Date.now();
    try {
      checkRateLimit('registry');
      validateRegistryKey(key);
      validateIdentifier(valueName, 'valueName');
      validateRegistryType(valueType);

      // Validate valueData based on type
      if (valueType === 'REG_DWORD' || valueType === 'REG_QWORD') {
        if (!/^\d+$/.test(valueData)) {
          throw new Error('Invalid value data: DWORD/QWORD must be numeric');
        }
      }

      this.logger.info(`Setting registry value: ${key}\\${valueName}`);

      const result = secureExec('reg.exe', ['add', key, '/v', valueName, '/t', valueType, '/d', valueData, '/f'], { timeout: 10000 });

      return {
        success: result.success,
        output: result.stdout,
        error: sanitizeErrorMessage(result.stderr, 'Set registry value'),
        duration_ms: Date.now() - startTime
      };
    } catch (error: any) {
      return {
        success: false,
        error: sanitizeErrorMessage(error.message, 'Set registry value'),
        duration_ms: Date.now() - startTime
      };
    }
  }

  async deleteRegistryValue(key: string, valueName: string): Promise<PrimitiveResult> {
    const startTime = Date.now();
    try {
      checkRateLimit('registry');
      validateRegistryKey(key);
      validateIdentifier(valueName, 'valueName');

      this.logger.info(`Deleting registry value: ${key}\\${valueName}`);

      const result = secureExec('reg.exe', ['delete', key, '/v', valueName, '/f'], { timeout: 10000 });

      return {
        success: result.success,
        output: result.stdout,
        error: sanitizeErrorMessage(result.stderr, 'Delete registry value'),
        duration_ms: Date.now() - startTime
      };
    } catch (error: any) {
      return {
        success: false,
        error: sanitizeErrorMessage(error.message, 'Delete registry value'),
        duration_ms: Date.now() - startTime
      };
    }
  }

  // ========================================
  // FILE OPERATIONS (with path restrictions)
  // ========================================

  async deleteFile(filePath: string): Promise<PrimitiveResult> {
    const startTime = Date.now();
    try {
      checkRateLimit('fileOps');

      // Validate and normalize path within allowed directories
      const normalizedPath = validateFilePath(filePath, 'filePath', ALLOWED_FILE_DIRS);

      // Check for symlink attack
      if (isSymlink(normalizedPath)) {
        throw new Error('Cannot delete symlinks for security reasons');
      }

      // Verify file exists
      if (!fs.existsSync(normalizedPath)) {
        return { success: false, error: 'File not found', duration_ms: Date.now() - startTime };
      }

      this.logger.info(`Deleting file: ${normalizedPath}`);

      // Use Node.js fs instead of shell command
      fs.unlinkSync(normalizedPath);

      return {
        success: true,
        output: 'File deleted',
        duration_ms: Date.now() - startTime
      };
    } catch (error: any) {
      return {
        success: false,
        error: sanitizeErrorMessage(error.message, 'Delete file'),
        duration_ms: Date.now() - startTime
      };
    }
  }

  async copyFile(source: string, destination: string): Promise<PrimitiveResult> {
    const startTime = Date.now();
    try {
      checkRateLimit('fileOps');

      // Validate paths
      const normalizedSource = validateFilePath(source, 'source');
      const normalizedDest = validateFilePath(destination, 'destination', ALLOWED_FILE_DIRS);

      // Check for symlink attack on source
      if (isSymlink(normalizedSource)) {
        throw new Error('Cannot copy from symlinks for security reasons');
      }

      // Verify source exists
      if (!fs.existsSync(normalizedSource)) {
        return { success: false, error: 'Source file not found', duration_ms: Date.now() - startTime };
      }

      this.logger.info(`Copying file: ${normalizedSource} -> ${normalizedDest}`);

      // Use Node.js fs instead of shell command
      fs.copyFileSync(normalizedSource, normalizedDest);

      return {
        success: true,
        output: 'File copied',
        duration_ms: Date.now() - startTime
      };
    } catch (error: any) {
      return {
        success: false,
        error: sanitizeErrorMessage(error.message, 'Copy file'),
        duration_ms: Date.now() - startTime
      };
    }
  }

  // ========================================
  // DIAGNOSTIC PRIMITIVES
  // ========================================

  /**
   * Get top processes by CPU usage
   */
  async getTopProcesses(count: number = 10): Promise<DiagnosticResult<ProcessInfo[]>> {
    const startTime = Date.now();
    const collected_at = new Date().toISOString();

    try {
      // Validate count
      if (!Number.isInteger(count) || count < 1 || count > 50) {
        count = 10;
      }

      const script = `
        Get-Process | Sort-Object CPU -Descending | Select-Object -First ${count} |
        ForEach-Object {
          [PSCustomObject]@{
            name = $_.ProcessName
            pid = $_.Id
            cpu_percent = [math]::Round($_.CPU, 2)
            memory_mb = [math]::Round($_.WorkingSet64 / 1MB, 2)
            thread_count = $_.Threads.Count
            handle_count = $_.HandleCount
            start_time = if ($_.StartTime) { $_.StartTime.ToString('o') } else { $null }
          }
        } | ConvertTo-Json -Compress
      `;

      const result = securePowerShell(script, { timeout: 15000 });

      if (result.success && result.stdout) {
        let data = JSON.parse(result.stdout);
        // Ensure array
        if (!Array.isArray(data)) data = [data];
        return { success: true, data, duration_ms: Date.now() - startTime, collected_at };
      }

      return { success: false, error: 'Failed to get process list', duration_ms: Date.now() - startTime, collected_at };
    } catch (error: any) {
      return { success: false, error: sanitizeErrorMessage(error.message, 'Get top processes'), duration_ms: Date.now() - startTime, collected_at };
    }
  }

  /**
   * Get processor/CPU details
   */
  async getProcessorDetails(): Promise<DiagnosticResult<ProcessorInfo>> {
    const startTime = Date.now();
    const collected_at = new Date().toISOString();

    try {
      const script = `
        $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
        $load = (Get-Counter '\\Processor(_Total)\\% Processor Time' -ErrorAction SilentlyContinue).CounterSamples[0].CookedValue
        [PSCustomObject]@{
          name = $cpu.Name
          load_percent = [math]::Round($load, 2)
          max_clock_mhz = $cpu.MaxClockSpeed
          current_clock_mhz = $cpu.CurrentClockSpeed
          cores = $cpu.NumberOfCores
          logical_processors = $cpu.NumberOfLogicalProcessors
        } | ConvertTo-Json -Compress
      `;

      const result = securePowerShell(script, { timeout: 10000 });

      if (result.success && result.stdout) {
        const data = JSON.parse(result.stdout);
        return { success: true, data, duration_ms: Date.now() - startTime, collected_at };
      }

      return { success: false, error: 'Failed to get processor details', duration_ms: Date.now() - startTime, collected_at };
    } catch (error: any) {
      return { success: false, error: sanitizeErrorMessage(error.message, 'Get processor details'), duration_ms: Date.now() - startTime, collected_at };
    }
  }

  /**
   * Get recently installed programs
   */
  async getRecentInstalls(days: number = 7): Promise<DiagnosticResult<InstalledProgram[]>> {
    const startTime = Date.now();
    const collected_at = new Date().toISOString();

    try {
      if (!Number.isInteger(days) || days < 1 || days > 90) {
        days = 7;
      }

      const script = `
        $cutoff = (Get-Date).AddDays(-${days})
        Get-CimInstance Win32_Product | Where-Object { $_.InstallDate -and [datetime]::ParseExact($_.InstallDate, 'yyyyMMdd', $null) -gt $cutoff } |
        Select-Object -First 20 |
        ForEach-Object {
          [PSCustomObject]@{
            name = $_.Name
            version = $_.Version
            install_date = $_.InstallDate
            publisher = $_.Vendor
          }
        } | ConvertTo-Json -Compress
      `;

      const result = securePowerShell(script, { timeout: 30000 });

      if (result.success) {
        let data: InstalledProgram[] = [];
        if (result.stdout && result.stdout.trim()) {
          data = JSON.parse(result.stdout);
          if (!Array.isArray(data)) data = [data];
        }
        return { success: true, data, duration_ms: Date.now() - startTime, collected_at };
      }

      return { success: false, error: 'Failed to get recent installs', duration_ms: Date.now() - startTime, collected_at };
    } catch (error: any) {
      return { success: false, error: sanitizeErrorMessage(error.message, 'Get recent installs'), duration_ms: Date.now() - startTime, collected_at };
    }
  }

  /**
   * Get detailed service information
   */
  async getServiceDetails(serviceName: string): Promise<DiagnosticResult<ServiceInfo>> {
    const startTime = Date.now();
    const collected_at = new Date().toISOString();

    try {
      validateIdentifier(serviceName, 'serviceName');

      const script = `
        $svc = Get-Service -Name '${serviceName.replace(/'/g, "''")}' -ErrorAction Stop
        $wmiSvc = Get-CimInstance Win32_Service -Filter "Name='${serviceName.replace(/'/g, "''")}'"
        $deps = $svc.ServicesDependedOn | ForEach-Object { $_.Name }
        $dependents = $svc.DependentServices | ForEach-Object { $_.Name }
        [PSCustomObject]@{
          name = $svc.Name
          display_name = $svc.DisplayName
          status = $svc.Status.ToString()
          start_type = $svc.StartType.ToString()
          account = $wmiSvc.StartName
          path_to_executable = $wmiSvc.PathName
          dependencies = @($deps)
          dependents = @($dependents)
        } | ConvertTo-Json -Compress
      `;

      const result = securePowerShell(script, { timeout: 10000 });

      if (result.success && result.stdout) {
        const data = JSON.parse(result.stdout);
        return { success: true, data, duration_ms: Date.now() - startTime, collected_at };
      }

      return { success: false, error: 'Service not found or failed to query', duration_ms: Date.now() - startTime, collected_at };
    } catch (error: any) {
      return { success: false, error: sanitizeErrorMessage(error.message, 'Get service details'), duration_ms: Date.now() - startTime, collected_at };
    }
  }

  /**
   * Get service-related event logs
   */
  async getServiceEventLogs(serviceName: string, hours: number = 24): Promise<DiagnosticResult<ServiceEvent[]>> {
    const startTime = Date.now();
    const collected_at = new Date().toISOString();

    try {
      validateIdentifier(serviceName, 'serviceName');
      if (!Number.isInteger(hours) || hours < 1 || hours > 168) {
        hours = 24;
      }

      const script = `
        $startTime = (Get-Date).AddHours(-${hours})
        Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$startTime} -MaxEvents 100 -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -like '*${serviceName.replace(/'/g, "''")}*' } |
        Select-Object -First 20 |
        ForEach-Object {
          [PSCustomObject]@{
            timestamp = $_.TimeCreated.ToString('o')
            level = $_.LevelDisplayName
            event_id = $_.Id
            message = $_.Message.Substring(0, [Math]::Min(200, $_.Message.Length))
          }
        } | ConvertTo-Json -Compress
      `;

      const result = securePowerShell(script, { timeout: 15000 });

      if (result.success) {
        let data: ServiceEvent[] = [];
        if (result.stdout && result.stdout.trim()) {
          data = JSON.parse(result.stdout);
          if (!Array.isArray(data)) data = [data];
        }
        return { success: true, data, duration_ms: Date.now() - startTime, collected_at };
      }

      return { success: false, error: 'Failed to query event logs', duration_ms: Date.now() - startTime, collected_at };
    } catch (error: any) {
      return { success: false, error: sanitizeErrorMessage(error.message, 'Get service events'), duration_ms: Date.now() - startTime, collected_at };
    }
  }

  /**
   * Get services that should be running but aren't
   */
  async getFailedServices(): Promise<DiagnosticResult<ServiceInfo[]>> {
    const startTime = Date.now();
    const collected_at = new Date().toISOString();

    try {
      const script = `
        Get-Service | Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -ne 'Running' } |
        Select-Object -First 20 |
        ForEach-Object {
          $wmiSvc = Get-CimInstance Win32_Service -Filter "Name='$($_.Name)'" -ErrorAction SilentlyContinue
          [PSCustomObject]@{
            name = $_.Name
            display_name = $_.DisplayName
            status = $_.Status.ToString()
            start_type = $_.StartType.ToString()
            account = $wmiSvc.StartName
            dependencies = @()
            dependents = @()
          }
        } | ConvertTo-Json -Compress
      `;

      const result = securePowerShell(script, { timeout: 15000 });

      if (result.success) {
        let data: ServiceInfo[] = [];
        if (result.stdout && result.stdout.trim()) {
          data = JSON.parse(result.stdout);
          if (!Array.isArray(data)) data = [data];
        }
        return { success: true, data, duration_ms: Date.now() - startTime, collected_at };
      }

      return { success: false, error: 'Failed to query services', duration_ms: Date.now() - startTime, collected_at };
    } catch (error: any) {
      return { success: false, error: sanitizeErrorMessage(error.message, 'Get failed services'), duration_ms: Date.now() - startTime, collected_at };
    }
  }

  /**
   * Get disk usage by drive
   */
  async getDiskUsage(): Promise<DiagnosticResult<DiskUsageInfo[]>> {
    const startTime = Date.now();
    const collected_at = new Date().toISOString();

    try {
      const script = `
        Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" |
        ForEach-Object {
          [PSCustomObject]@{
            drive = $_.DeviceID
            label = $_.VolumeName
            file_system = $_.FileSystem
            total_gb = [math]::Round($_.Size / 1GB, 2)
            used_gb = [math]::Round(($_.Size - $_.FreeSpace) / 1GB, 2)
            free_gb = [math]::Round($_.FreeSpace / 1GB, 2)
            percent_free = [math]::Round(($_.FreeSpace / $_.Size) * 100, 2)
          }
        } | ConvertTo-Json -Compress
      `;

      const result = securePowerShell(script, { timeout: 10000 });

      if (result.success && result.stdout) {
        let data = JSON.parse(result.stdout);
        if (!Array.isArray(data)) data = [data];
        return { success: true, data, duration_ms: Date.now() - startTime, collected_at };
      }

      return { success: false, error: 'Failed to get disk usage', duration_ms: Date.now() - startTime, collected_at };
    } catch (error: any) {
      return { success: false, error: sanitizeErrorMessage(error.message, 'Get disk usage'), duration_ms: Date.now() - startTime, collected_at };
    }
  }

  /**
   * Get largest folders on a drive
   */
  async getLargestFolders(drive: string = 'C:', topN: number = 10): Promise<DiagnosticResult<FolderSize[]>> {
    const startTime = Date.now();
    const collected_at = new Date().toISOString();

    try {
      // Validate drive letter
      if (!/^[A-Za-z]:$/.test(drive)) {
        drive = 'C:';
      }
      if (!Number.isInteger(topN) || topN < 1 || topN > 20) {
        topN = 10;
      }

      const script = `
        $folders = @(
          "${drive}\\Users",
          "${drive}\\Windows\\Temp",
          "${drive}\\Windows\\SoftwareDistribution",
          "${drive}\\ProgramData",
          "${drive}\\Program Files",
          "${drive}\\Program Files (x86)"
        )
        $results = @()
        foreach ($folder in $folders) {
          if (Test-Path $folder) {
            $size = (Get-ChildItem -Path $folder -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
            $results += [PSCustomObject]@{
              path = $folder
              size_gb = [math]::Round($size / 1GB, 2)
            }
          }
        }
        $results | Sort-Object size_gb -Descending | Select-Object -First ${topN} | ConvertTo-Json -Compress
      `;

      const result = securePowerShell(script, { timeout: 60000 });

      if (result.success) {
        let data: FolderSize[] = [];
        if (result.stdout && result.stdout.trim()) {
          data = JSON.parse(result.stdout);
          if (!Array.isArray(data)) data = [data];
        }
        return { success: true, data, duration_ms: Date.now() - startTime, collected_at };
      }

      return { success: false, error: 'Failed to analyze folders', duration_ms: Date.now() - startTime, collected_at };
    } catch (error: any) {
      return { success: false, error: sanitizeErrorMessage(error.message, 'Get largest folders'), duration_ms: Date.now() - startTime, collected_at };
    }
  }

  /**
   * Get recent file growth
   */
  async getRecentFileGrowth(drive: string = 'C:', hours: number = 24): Promise<DiagnosticResult<FileGrowth[]>> {
    const startTime = Date.now();
    const collected_at = new Date().toISOString();

    try {
      if (!/^[A-Za-z]:$/.test(drive)) {
        drive = 'C:';
      }
      if (!Number.isInteger(hours) || hours < 1 || hours > 168) {
        hours = 24;
      }

      const script = `
        $cutoff = (Get-Date).AddHours(-${hours})
        $folders = @("${drive}\\Users", "${drive}\\Windows\\Temp", "${drive}\\ProgramData")
        $results = @()
        foreach ($folder in $folders) {
          if (Test-Path $folder) {
            $newFiles = Get-ChildItem -Path $folder -Recurse -File -ErrorAction SilentlyContinue |
              Where-Object { $_.CreationTime -gt $cutoff } |
              Sort-Object Length -Descending | Select-Object -First 5
            $totalGrowth = ($newFiles | Measure-Object -Property Length -Sum).Sum
            $results += [PSCustomObject]@{
              path = $folder
              growth_mb = [math]::Round($totalGrowth / 1MB, 2)
              largest_new_files = @($newFiles | ForEach-Object {
                [PSCustomObject]@{
                  name = $_.Name
                  size_mb = [math]::Round($_.Length / 1MB, 2)
                  created = $_.CreationTime.ToString('o')
                }
              })
            }
          }
        }
        $results | Where-Object { $_.growth_mb -gt 0 } | ConvertTo-Json -Depth 3 -Compress
      `;

      const result = securePowerShell(script, { timeout: 60000 });

      if (result.success) {
        let data: FileGrowth[] = [];
        if (result.stdout && result.stdout.trim()) {
          data = JSON.parse(result.stdout);
          if (!Array.isArray(data)) data = [data];
        }
        return { success: true, data, duration_ms: Date.now() - startTime, collected_at };
      }

      return { success: false, error: 'Failed to analyze file growth', duration_ms: Date.now() - startTime, collected_at };
    } catch (error: any) {
      return { success: false, error: sanitizeErrorMessage(error.message, 'Get file growth'), duration_ms: Date.now() - startTime, collected_at };
    }
  }

  /**
   * Get SMART disk health data
   */
  async getSMARTData(): Promise<DiagnosticResult<SMARTData[]>> {
    const startTime = Date.now();
    const collected_at = new Date().toISOString();

    try {
      const script = `
        Get-CimInstance -Namespace root\\wmi -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction SilentlyContinue |
        ForEach-Object {
          $disk = Get-CimInstance Win32_DiskDrive | Where-Object { $_.Index -eq $_.InstanceName.Split('_')[-1] } | Select-Object -First 1
          [PSCustomObject]@{
            drive = $disk.DeviceID
            model = $disk.Model
            serial = $disk.SerialNumber
            health_status = if ($_.PredictFailure) { 'Pred Fail' } else { 'OK' }
          }
        } | ConvertTo-Json -Compress
      `;

      const result = securePowerShell(script, { timeout: 15000 });

      if (result.success) {
        let data: SMARTData[] = [];
        if (result.stdout && result.stdout.trim()) {
          try {
            data = JSON.parse(result.stdout);
            if (!Array.isArray(data)) data = [data];
          } catch {
            // SMART may not be available
          }
        }
        return { success: true, data, duration_ms: Date.now() - startTime, collected_at };
      }

      return { success: true, data: [], duration_ms: Date.now() - startTime, collected_at };
    } catch (error: any) {
      return { success: false, error: sanitizeErrorMessage(error.message, 'Get SMART data'), duration_ms: Date.now() - startTime, collected_at };
    }
  }

  /**
   * Get top memory consuming processes
   */
  async getMemoryConsumers(topN: number = 10): Promise<DiagnosticResult<MemoryConsumer[]>> {
    const startTime = Date.now();
    const collected_at = new Date().toISOString();

    try {
      if (!Number.isInteger(topN) || topN < 1 || topN > 50) {
        topN = 10;
      }

      const script = `
        Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First ${topN} |
        ForEach-Object {
          [PSCustomObject]@{
            name = $_.ProcessName
            pid = $_.Id
            working_set_mb = [math]::Round($_.WorkingSet64 / 1MB, 2)
            private_bytes_mb = [math]::Round($_.PrivateMemorySize64 / 1MB, 2)
            handle_count = $_.HandleCount
          }
        } | ConvertTo-Json -Compress
      `;

      const result = securePowerShell(script, { timeout: 10000 });

      if (result.success && result.stdout) {
        let data = JSON.parse(result.stdout);
        if (!Array.isArray(data)) data = [data];
        return { success: true, data, duration_ms: Date.now() - startTime, collected_at };
      }

      return { success: false, error: 'Failed to get memory consumers', duration_ms: Date.now() - startTime, collected_at };
    } catch (error: any) {
      return { success: false, error: sanitizeErrorMessage(error.message, 'Get memory consumers'), duration_ms: Date.now() - startTime, collected_at };
    }
  }

  /**
   * Get page file status
   */
  async getPageFileStatus(): Promise<DiagnosticResult<PageFileStatus>> {
    const startTime = Date.now();
    const collected_at = new Date().toISOString();

    try {
      const script = `
        $pf = Get-CimInstance Win32_PageFileUsage | Select-Object -First 1
        [PSCustomObject]@{
          location = $pf.Name
          allocated_mb = $pf.AllocatedBaseSize
          used_mb = $pf.CurrentUsage
          peak_mb = $pf.PeakUsage
          percent_used = [math]::Round(($pf.CurrentUsage / $pf.AllocatedBaseSize) * 100, 2)
        } | ConvertTo-Json -Compress
      `;

      const result = securePowerShell(script, { timeout: 10000 });

      if (result.success && result.stdout) {
        const data = JSON.parse(result.stdout);
        return { success: true, data, duration_ms: Date.now() - startTime, collected_at };
      }

      return { success: false, error: 'Failed to get page file status', duration_ms: Date.now() - startTime, collected_at };
    } catch (error: any) {
      return { success: false, error: sanitizeErrorMessage(error.message, 'Get page file status'), duration_ms: Date.now() - startTime, collected_at };
    }
  }

  /**
   * Get system memory details
   */
  async getSystemMemoryDetails(): Promise<DiagnosticResult<SystemMemoryInfo>> {
    const startTime = Date.now();
    const collected_at = new Date().toISOString();

    try {
      const script = `
        $os = Get-CimInstance Win32_OperatingSystem
        $mem = Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum
        [PSCustomObject]@{
          total_mb = [math]::Round($mem.Sum / 1MB, 2)
          available_mb = [math]::Round($os.FreePhysicalMemory / 1KB, 2)
          committed_mb = [math]::Round(($os.TotalVirtualMemorySize - $os.FreeVirtualMemory) / 1KB, 2)
          cached_mb = 0
          percent_used = [math]::Round((1 - ($os.FreePhysicalMemory * 1KB / $mem.Sum)) * 100, 2)
        } | ConvertTo-Json -Compress
      `;

      const result = securePowerShell(script, { timeout: 10000 });

      if (result.success && result.stdout) {
        const data = JSON.parse(result.stdout);
        return { success: true, data, duration_ms: Date.now() - startTime, collected_at };
      }

      return { success: false, error: 'Failed to get memory details', duration_ms: Date.now() - startTime, collected_at };
    } catch (error: any) {
      return { success: false, error: sanitizeErrorMessage(error.message, 'Get memory details'), duration_ms: Date.now() - startTime, collected_at };
    }
  }

  /**
   * Get network adapter information
   */
  async getNetworkAdapters(): Promise<DiagnosticResult<NetworkAdapterInfo[]>> {
    const startTime = Date.now();
    const collected_at = new Date().toISOString();

    try {
      const script = `
        Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -or $_.Status -eq 'Disconnected' } |
        ForEach-Object {
          $config = Get-NetIPConfiguration -InterfaceIndex $_.ifIndex -ErrorAction SilentlyContinue
          [PSCustomObject]@{
            name = $_.Name
            description = $_.InterfaceDescription
            status = $_.Status
            link_speed_mbps = [math]::Round($_.LinkSpeed.Replace(' Gbps','000').Replace(' Mbps','').Replace(' Kbps','') / 1, 0)
            ip_addresses = @($config.IPv4Address.IPAddress)
            mac_address = $_.MacAddress
            dhcp_enabled = $config.NetIPv4Interface.Dhcp -eq 'Enabled'
            dns_servers = @($config.DNSServer.ServerAddresses)
            default_gateway = $config.IPv4DefaultGateway.NextHop
          }
        } | ConvertTo-Json -Compress
      `;

      const result = securePowerShell(script, { timeout: 15000 });

      if (result.success) {
        let data: NetworkAdapterInfo[] = [];
        if (result.stdout && result.stdout.trim()) {
          data = JSON.parse(result.stdout);
          if (!Array.isArray(data)) data = [data];
        }
        return { success: true, data, duration_ms: Date.now() - startTime, collected_at };
      }

      return { success: false, error: 'Failed to get network adapters', duration_ms: Date.now() - startTime, collected_at };
    } catch (error: any) {
      return { success: false, error: sanitizeErrorMessage(error.message, 'Get network adapters'), duration_ms: Date.now() - startTime, collected_at };
    }
  }

  /**
   * Test DNS resolution
   */
  async getDNSResolutionTest(hosts: string[] = ['google.com', 'microsoft.com']): Promise<DiagnosticResult<DNSTestResult[]>> {
    const startTime = Date.now();
    const collected_at = new Date().toISOString();

    try {
      // Validate hosts
      const safeHosts = hosts.filter(h => /^[a-zA-Z0-9.-]+$/.test(h)).slice(0, 5);
      if (safeHosts.length === 0) {
        safeHosts.push('google.com', 'microsoft.com');
      }

      const hostList = safeHosts.map(h => `'${h}'`).join(',');
      const script = `
        @(${hostList}) | ForEach-Object {
          $host = $_
          $start = Get-Date
          try {
            $result = Resolve-DnsName -Name $host -Type A -ErrorAction Stop
            $elapsed = ((Get-Date) - $start).TotalMilliseconds
            [PSCustomObject]@{
              host = $host
              resolved = $true
              ip_addresses = @($result.IPAddress)
              response_time_ms = [math]::Round($elapsed, 0)
            }
          } catch {
            [PSCustomObject]@{
              host = $host
              resolved = $false
              error = $_.Exception.Message.Substring(0, [Math]::Min(100, $_.Exception.Message.Length))
            }
          }
        } | ConvertTo-Json -Compress
      `;

      const result = securePowerShell(script, { timeout: 30000 });

      if (result.success) {
        let data: DNSTestResult[] = [];
        if (result.stdout && result.stdout.trim()) {
          data = JSON.parse(result.stdout);
          if (!Array.isArray(data)) data = [data];
        }
        return { success: true, data, duration_ms: Date.now() - startTime, collected_at };
      }

      return { success: false, error: 'Failed to test DNS', duration_ms: Date.now() - startTime, collected_at };
    } catch (error: any) {
      return { success: false, error: sanitizeErrorMessage(error.message, 'DNS resolution test'), duration_ms: Date.now() - startTime, collected_at };
    }
  }

  /**
   * Get routing table
   */
  async getRouteTable(): Promise<DiagnosticResult<RouteEntry[]>> {
    const startTime = Date.now();
    const collected_at = new Date().toISOString();

    try {
      const script = `
        Get-NetRoute -AddressFamily IPv4 | Select-Object -First 20 |
        ForEach-Object {
          [PSCustomObject]@{
            destination = $_.DestinationPrefix
            netmask = ''
            gateway = $_.NextHop
            interface_addr = $_.InterfaceAlias
            metric = $_.RouteMetric
          }
        } | ConvertTo-Json -Compress
      `;

      const result = securePowerShell(script, { timeout: 10000 });

      if (result.success) {
        let data: RouteEntry[] = [];
        if (result.stdout && result.stdout.trim()) {
          data = JSON.parse(result.stdout);
          if (!Array.isArray(data)) data = [data];
        }
        return { success: true, data, duration_ms: Date.now() - startTime, collected_at };
      }

      return { success: false, error: 'Failed to get route table', duration_ms: Date.now() - startTime, collected_at };
    } catch (error: any) {
      return { success: false, error: sanitizeErrorMessage(error.message, 'Get route table'), duration_ms: Date.now() - startTime, collected_at };
    }
  }

  /**
   * Test connectivity to endpoints
   */
  async getConnectivityTest(endpoints: string[] = ['https://www.google.com']): Promise<DiagnosticResult<ConnectivityTestResult[]>> {
    const startTime = Date.now();
    const collected_at = new Date().toISOString();

    try {
      // Validate endpoints - must be https URLs
      const safeEndpoints = endpoints
        .filter(e => /^https:\/\/[a-zA-Z0-9.-]+/.test(e))
        .slice(0, 3);
      if (safeEndpoints.length === 0) {
        safeEndpoints.push('https://www.google.com');
      }

      const endpointList = safeEndpoints.map(e => `'${e}'`).join(',');
      const script = `
        @(${endpointList}) | ForEach-Object {
          $url = $_
          $start = Get-Date
          try {
            $response = Invoke-WebRequest -Uri $url -Method Head -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
            $elapsed = ((Get-Date) - $start).TotalMilliseconds
            [PSCustomObject]@{
              endpoint = $url
              reachable = $true
              response_time_ms = [math]::Round($elapsed, 0)
              status_code = $response.StatusCode
            }
          } catch {
            [PSCustomObject]@{
              endpoint = $url
              reachable = $false
              error = $_.Exception.Message.Substring(0, [Math]::Min(100, $_.Exception.Message.Length))
            }
          }
        } | ConvertTo-Json -Compress
      `;

      const result = securePowerShell(script, { timeout: 45000 });

      if (result.success) {
        let data: ConnectivityTestResult[] = [];
        if (result.stdout && result.stdout.trim()) {
          data = JSON.parse(result.stdout);
          if (!Array.isArray(data)) data = [data];
        }
        return { success: true, data, duration_ms: Date.now() - startTime, collected_at };
      }

      return { success: false, error: 'Failed to test connectivity', duration_ms: Date.now() - startTime, collected_at };
    } catch (error: any) {
      return { success: false, error: sanitizeErrorMessage(error.message, 'Connectivity test'), duration_ms: Date.now() - startTime, collected_at };
    }
  }

  /**
   * Get system snapshot for general troubleshooting
   */
  async getSystemSnapshot(): Promise<DiagnosticResult<SystemSnapshot>> {
    const startTime = Date.now();
    const collected_at = new Date().toISOString();

    try {
      const script = `
        $os = Get-CimInstance Win32_OperatingSystem
        $cs = Get-CimInstance Win32_ComputerSystem
        $uptime = (Get-Date) - $os.LastBootUpTime
        $autoStopped = (Get-Service | Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -ne 'Running' }).Count
        $running = (Get-Service | Where-Object { $_.Status -eq 'Running' }).Count
        $pendingReboot = Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending'
        [PSCustomObject]@{
          hostname = $cs.Name
          os_version = $os.Caption
          os_build = $os.BuildNumber
          uptime_hours = [math]::Round($uptime.TotalHours, 2)
          last_boot = $os.LastBootUpTime.ToString('o')
          pending_reboot = $pendingReboot
          running_services_count = $running
          stopped_auto_services_count = $autoStopped
        } | ConvertTo-Json -Compress
      `;

      const result = securePowerShell(script, { timeout: 15000 });

      if (result.success && result.stdout) {
        const data = JSON.parse(result.stdout);
        return { success: true, data, duration_ms: Date.now() - startTime, collected_at };
      }

      return { success: false, error: 'Failed to get system snapshot', duration_ms: Date.now() - startTime, collected_at };
    } catch (error: any) {
      return { success: false, error: sanitizeErrorMessage(error.message, 'Get system snapshot'), duration_ms: Date.now() - startTime, collected_at };
    }
  }

  /**
   * Get recent event log errors
   */
  async getRecentEventLogErrors(hours: number = 24): Promise<DiagnosticResult<EventLogError[]>> {
    const startTime = Date.now();
    const collected_at = new Date().toISOString();

    try {
      if (!Number.isInteger(hours) || hours < 1 || hours > 168) {
        hours = 24;
      }

      const script = `
        $startTime = (Get-Date).AddHours(-${hours})
        @('System', 'Application') | ForEach-Object {
          $logName = $_
          Get-WinEvent -FilterHashtable @{LogName=$logName; Level=1,2; StartTime=$startTime} -MaxEvents 25 -ErrorAction SilentlyContinue |
          ForEach-Object {
            [PSCustomObject]@{
              log_name = $logName
              source = $_.ProviderName
              event_id = $_.Id
              level = $_.LevelDisplayName
              timestamp = $_.TimeCreated.ToString('o')
              message = $_.Message.Substring(0, [Math]::Min(200, $_.Message.Length))
            }
          }
        } | Sort-Object timestamp -Descending | Select-Object -First 30 | ConvertTo-Json -Compress
      `;

      const result = securePowerShell(script, { timeout: 20000 });

      if (result.success) {
        let data: EventLogError[] = [];
        if (result.stdout && result.stdout.trim()) {
          data = JSON.parse(result.stdout);
          if (!Array.isArray(data)) data = [data];
        }
        return { success: true, data, duration_ms: Date.now() - startTime, collected_at };
      }

      return { success: false, error: 'Failed to query event logs', duration_ms: Date.now() - startTime, collected_at };
    } catch (error: any) {
      return { success: false, error: sanitizeErrorMessage(error.message, 'Get event log errors'), duration_ms: Date.now() - startTime, collected_at };
    }
  }
}
