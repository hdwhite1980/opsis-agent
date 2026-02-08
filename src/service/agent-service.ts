// agent-service.ts - Production OPSIS Agent Service with Tiered Intelligence Integration
import * as os from 'os';
import * as fs from 'fs';
import * as path from 'path';
import * as https from 'https';
import * as crypto from 'crypto';
import { exec } from 'child_process';
import { promisify } from 'util';
import WebSocket from 'ws';
import { getServiceLogger, Logger } from '../common/logger';
import EventMonitor, { EventLogEntry, RunbookMatch, Runbook } from './event-monitor';
import { TicketDatabase, Ticket } from './ticket-database';
import { SystemMonitor, SystemSignal } from './system-monitor';
import { IPCServer } from './ipc-server';
import { RemediationMemory } from './remediation-memory';
import { GuiLauncher } from './gui-launcher';
import { PatternDetector } from './pattern-detector';

// NEW IMPORTS - Tiered Intelligence Components
import { SignatureGenerator, DeviceSignature } from './signature-generator';
import { EscalationProtocol, EscalationPayload, ServerDecision } from './escalation-protocol';
import { RunbookClassifier, RiskClass } from './runbook-classifier';
import { ActionTicketManager } from './action-ticket-manager';
import { TroubleshootingRunner, DiagnosticData } from './troubleshooting-runner';
import { StateTracker, StateChangeEvent, SeverityEscalationEvent } from './state-tracker';
import { MaintenanceWindowManager, MaintenanceWindow } from './maintenance-windows';

// Security imports
import {
  getApiKey,
  getHmacSecret,
  storeCredentialsFromSetup,
  verifyPlaybook,
  verifyDiagnosticRequest,
  validatePlaybook,
  validateDiagnosticRequest,
  handleKeyRotation,
  createRotationAck,
  createRotationError,
  isHmacConfigured,
  tryParseJSON
} from '../security';

const execAsync = promisify(exec);

// Protected processes and services that must NEVER be killed/stopped
const PROTECTED_PROCESSES: ReadonlySet<string> = new Set([
  'svchost.exe', 'lsass.exe', 'csrss.exe', 'winlogon.exe',
  'dwm.exe', 'explorer.exe', 'services.exe', 'smss.exe',
  'wininit.exe', 'system', 'system idle process',
  'conhost.exe', 'ntoskrnl.exe'
]);

const PROTECTED_SERVICES: ReadonlySet<string> = new Set([
  'rpcss', 'dcomlaunch', 'lsm', 'samss', 'eventlog',
  'plugplay', 'power', 'profiling service', 'winmgmt',
  'cryptsvc', 'lanmanserver', 'lanmanworkstation',
  'schedule', 'spooler', 'w32time', 'wuauserv'
]);

function isProtectedProcess(name: string): boolean {
  return PROTECTED_PROCESSES.has(name.toLowerCase());
}

function isProtectedService(name: string): boolean {
  return PROTECTED_SERVICES.has(name.toLowerCase());
}

// Helper function for HTTP requests
function httpsRequest(url: string, options: any): Promise<any> {
  return new Promise((resolve, reject) => {
    const req = https.request(url, options, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (err) {
          resolve(data);
        }
      });
    });
    req.on('error', reject);
    if (options.body) {
      req.write(options.body);
    }
    req.end();
  });
}

interface UpdateCheckResponse {
  updateAvailable: boolean;
  version?: string;
  downloadUrl?: string;
}

interface PlaybookTask {
  id: string;
  name: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
  source: 'server' | 'admin' | 'local';
  steps: PlaybookStep[];
  createdAt: Date;
}

interface PlaybookStep {
  type: 'powershell' | 'registry' | 'service' | 'file' | 'wmi' | 'diagnostic' | 'reboot' | 'user-prompt';
  action: string;
  params: Record<string, any>;
  timeout?: number;
  requiresApproval?: boolean;
  allowFailure?: boolean;
}

/**
 * Detect verification/check steps that should not fail the playbook.
 * These are typically Get-Process/Get-Service commands that run after
 * a kill/stop action to confirm the target is gone or restarted.
 * An empty result (process not found) is the expected success case.
 */
export function isVerificationStep(step: PlaybookStep, allSteps: PlaybookStep[], index: number): boolean {
  if (step.type !== 'powershell') return false;

  const action = step.action.toLowerCase();

  // Pattern: Get-Process after a Stop-Process / kill step
  if (action.includes('get-process')) {
    for (let i = index - 1; i >= 0; i--) {
      const prev = allSteps[i].action.toLowerCase();
      if (prev.includes('stop-process') || prev.includes('kill') || prev.includes('taskkill')) {
        return true;
      }
    }
  }

  // Pattern: Get-Service after a service start/stop/restart step
  if (action.includes('get-service')) {
    for (let i = index - 1; i >= 0; i--) {
      const prev = allSteps[i].action.toLowerCase();
      if (prev.includes('start-service') || prev.includes('stop-service') ||
          prev.includes('restart-service') || prev.includes('net start') || prev.includes('net stop')) {
        return true;
      }
    }
  }

  return false;
}

interface AgentConfig {
  serverUrl?: string;
  autoConnect: boolean;
  autoUpdate: boolean;
  autoRemediation: boolean;
  confidenceThreshold: number;
  updateCheckInterval: number; // minutes
  apiKey?: string;
}

interface DeviceInfo {
  device_id: string;
  tenant_id: string;
  role: string;
  server_url?: string;
  websocket_url?: string;
}

interface ServerConfig {
  monitoring: {
    heartbeat_interval: number;
    telemetry_interval: number;
    health_check_interval: number;
  };
  thresholds: {
    cpu_warning: number;
    cpu_critical: number;
    memory_warning: number;
    memory_critical: number;
    disk_warning: number;
    disk_critical: number;
  };
  features: {
    autonomous_remediation: boolean;
    ai_enabled: boolean;
    proactive_monitoring: boolean;
    auto_update: boolean;
  };
}

class OPSISAgentService {
  private config: AgentConfig;
  private ws: WebSocket | null = null;
  private playbookQueue: PlaybookTask[] = [];
  private isExecutingPlaybook = false;
  private updateCheckTimer: NodeJS.Timeout | null = null;
  private patternAnalysisTimer: NodeJS.Timeout | null = null;
  private readonly baseDir: string;
  private readonly configPath: string;
  private readonly dataDir: string;
  private readonly logsDir: string;
  private readonly runbooksDir: string;
  private logger: Logger;
  private eventMonitor: EventMonitor;
  private systemMonitor: SystemMonitor;
  private ticketDb: TicketDatabase;
  private ipcServer: IPCServer;
  private guiLauncher: GuiLauncher;
  private remediationMemory: RemediationMemory;
  private serviceAlerts: any[] = [];
  private patternDetector: PatternDetector;
  private activeTickets: Map<string, string> = new Map(); // playbookId -> ticketId
  private suppressedServices: Set<string> = new Set(); // Services that should not be auto-restarted

  // Safe services that can be stopped from GUI without corrupting OS
  private static readonly SAFE_TO_STOP_SERVICES: ReadonlySet<string> = new Set([
    'Spooler', 'W32Time', 'BITS', 'wuauserv', 'gpsvc', 'Dnscache',
    'WSearch', 'Themes', 'TabletInputService', 'Fax', 'MapsBroker',
    'DiagTrack', 'dmwappushservice', 'SysMain', 'WbioSrvc', 'WerSvc'
  ]);

  // NEW PROPERTIES - Tiered Intelligence
  private signatureGenerator: SignatureGenerator;
  private escalationProtocol: EscalationProtocol;
  private runbookClassifier: RunbookClassifier;
  private actionTicketManager: ActionTicketManager;
  private troubleshootingRunner: TroubleshootingRunner;
  private deviceInfo: DeviceInfo;
  private recentActions: Array<{ 
    playbook_id: string; 
    result: 'success' | 'failure' | 'partial'; 
    timestamp: string;
  }> = [];
  private pendingEscalations: Map<string, DeviceSignature> = new Map(); // signature_id -> signature
  private pendingRunbooks: Map<string, RunbookMatch> = new Map(); // signature_id -> matched runbook
  private escalationCooldowns: Map<string, number> = new Map(); // signature_id -> last escalated timestamp
  private readonly ESCALATION_COOLDOWN_MS = 5 * 60 * 1000; // 5 minutes
  private escalationBatch: Array<{signature: DeviceSignature, runbook: RunbookMatch | null, diagnosticData?: DiagnosticData | null}> = [];
  private batchTimer: NodeJS.Timeout | null = null;
  private readonly BATCH_FLUSH_MS = 10000; // 10 seconds

  // Reconnect backoff state
  private reconnectAttempts: number = 0;
  private readonly RECONNECT_BASE_MS = 1000;
  private readonly RECONNECT_MAX_MS = 5 * 60 * 1000; // 5 minutes
  private sessionValid: boolean = true;

  // Server runbook storage
  private readonly serverRunbooksPath: string;
  private readonly REINVESTIGATION_THRESHOLD = 10; // Escalate for reinvestigation after 10 executions

  // Server-provided configuration (received via welcome message)
  private serverConfig: ServerConfig | null = null;
  private heartbeatTimer: NodeJS.Timeout | null = null;
  private welcomeTimeout: NodeJS.Timeout | null = null;
  private telemetryTimer: NodeJS.Timeout | null = null;
  private pendingPrompts: Map<string, { resolve: (response: string) => void; action_on_confirm?: string; timer?: NodeJS.Timeout }> = new Map();

  // Pending actions awaiting technician review
  private pendingActions: Map<string, {
    signature_id: string;
    signature: DeviceSignature;
    runbook: RunbookMatch | null;
    ticket_id: string;
    created_at: string;
    server_message: string;
  }> = new Map();
  private awaitingReviewSignals: Set<string> = new Set(); // Signals that shouldn't be re-escalated (awaiting technician)
  private readonly pendingActionsPath: string;

  // Monitoring trap agent features
  private stateTracker!: StateTracker;
  private maintenanceManager!: MaintenanceWindowManager;
  private severityEscalationTimer: NodeJS.Timeout | null = null;
  private dependencyRefreshTimer: NodeJS.Timeout | null = null;

  constructor() {
    // Determine base directory - handle both node.js and pkg compiled exe
    // When running as pkg exe, __dirname points to snapshot filesystem, so use cwd or exe path
    const isPkg = (process as any).pkg !== undefined;
    this.baseDir = isPkg
      ? process.cwd()  // WinSW sets working directory to app folder
      : path.join(__dirname, '..', '..');

    this.dataDir = path.join(this.baseDir, 'data');
    this.logsDir = path.join(this.baseDir, 'logs');
    this.runbooksDir = path.join(this.baseDir, 'runbooks');
    this.configPath = path.join(this.dataDir, 'agent.config.json');
    this.serverRunbooksPath = path.join(this.dataDir, 'server-runbooks.json');
    this.pendingActionsPath = path.join(this.dataDir, 'pending-actions.json');

    // Ensure directories exist
    [this.dataDir, this.logsDir, this.runbooksDir].forEach(dir => {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
    });

    // Initialize logger
    this.logger = getServiceLogger(this.logsDir);
    
    // Initialize GUI launcher
    this.guiLauncher = new GuiLauncher(this.logger, this.baseDir);

    // Initialize ticket database
    const dbPath = path.join(this.dataDir, 'tickets.json');
    this.ticketDb = new TicketDatabase(this.logger, dbPath);
    
    // Initialize remediation memory
    this.remediationMemory = new RemediationMemory(this.logger, this.dataDir);
    
    // Initialize pattern detector
    this.patternDetector = new PatternDetector(this.logger, this.dataDir);
    
    // NEW: Initialize Tiered Intelligence Components
    this.signatureGenerator = new SignatureGenerator(this.logger);
    this.escalationProtocol = new EscalationProtocol(this.logger);
    this.runbookClassifier = new RunbookClassifier(this.logger, this.runbooksDir);
    this.actionTicketManager = new ActionTicketManager(this.logger, this.ticketDb);
    this.troubleshootingRunner = new TroubleshootingRunner(this.logger, this.dataDir);
    this.stateTracker = new StateTracker(this.logger, this.dataDir);
    this.maintenanceManager = new MaintenanceWindowManager(this.logger, this.dataDir);

    // Load device info
    this.deviceInfo = this.loadDeviceInfo();
    
    this.config = this.loadConfig();
    this.logger.info('OPSIS Agent Service initializing...', {
      version: '1.0.0',
      platform: os.platform(),
      hostname: os.hostname(),
      device_id: this.deviceInfo.device_id,
      tenant_id: this.deviceInfo.tenant_id
    });

    // Initialize event monitor
    this.eventMonitor = new EventMonitor(
      this.logger,
      this.runbooksDir,
      (event, runbook) => this.handleIssueDetected(event, runbook),
      (event, reason) => this.handleEscalationNeeded(event, reason)
    );

    // Initialize system monitor
    this.systemMonitor = new SystemMonitor(
      this.logger,
      (issue) => this.handleSystemIssue(issue)
    );

    // Initialize IPC server for GUI communication
    this.ipcServer = new IPCServer(this.logger);
    this.setupIPCHandlers();
    
    // Send initial data when GUI connects
    this.ipcServer.onClientConnected((socket) => {
      try {
        const tickets = this.ticketDb.getTickets(100);
        const stats = this.ticketDb.getStatistics();

        const guiStats = {
          issuesDetected: stats.totalTickets,
          issuesEscalated: stats.escalatedTickets,
          successRate: stats.successRate,
          activeTickets: stats.openTickets
        };

        this.ipcServer.sendToClient(socket, {
          type: 'initial-data',
          data: {
            tickets,
            stats: guiStats,
            healthScores: this.patternDetector.getHealthScores(),
            correlations: this.patternDetector.getCorrelations(),
            patterns: this.patternDetector.getDetectedPatterns(),
            proactiveActions: this.patternDetector.getPendingActions(),
            serviceAlerts: this.serviceAlerts
          }
        });
      } catch (error) {
        this.logger.error('Error sending initial data to GUI', error);
      }
    });
  }

  // NEW METHOD: Load Device Info
  private loadDeviceInfo(): DeviceInfo {
    const configFile = path.join(this.dataDir, 'device.config.json');
    try {
      if (fs.existsSync(configFile)) {
        const content = fs.readFileSync(configFile, 'utf-8');
        const config = JSON.parse(content);
        this.logger?.info('Device config loaded', {
          device_id: config.device_id,
          tenant_id: config.tenant_id
        });
        return config;
      }
    } catch (error) {
      if (this.logger) {
        this.logger.error('Failed to load device info', error);
      }
    }
    
    // Default info if file doesn't exist
    const defaultInfo: DeviceInfo = {
      device_id: `device-${os.hostname()}`,
      tenant_id: 'tenant-1',
      role: 'workstation'
    };
    
    // Save default config
    try {
      fs.writeFileSync(configFile, JSON.stringify(defaultInfo, null, 2));
    } catch (error) {
      console.error('Failed to save default device config', error);
    }
    
    return defaultInfo;
  }

  private loadConfig(): AgentConfig {
    try {
      if (fs.existsSync(this.configPath)) {
        const data = fs.readFileSync(this.configPath, 'utf8');
        return JSON.parse(data);
      }
    } catch (err) {
      if (this.logger) {
        this.logger.error('Error loading config, using defaults', err);
      }
    }

    // Default config
    return {
      autoConnect: true,
      autoUpdate: true,
      autoRemediation: true,
      confidenceThreshold: 75,
      updateCheckInterval: 60
    };
  }

  private saveConfig(): void {
    try {
      // Remove sensitive fields before saving to disk
      const safeConfig = { ...this.config };
      delete safeConfig.apiKey; // Never save API key to disk
      fs.writeFileSync(this.configPath, JSON.stringify(safeConfig, null, 2));
      this.logger.info('Configuration saved');
    } catch (err) {
      this.logger.error('Error saving config', err);
    }
  }

  /**
   * Load API key and HMAC secret from Windows Credential Manager (keytar)
   * This is called during startup to retrieve secure credentials
   */
  private async loadSecureCredentials(): Promise<void> {
    try {
      // Load API key from keytar
      const apiKey = await getApiKey();
      if (apiKey) {
        this.config.apiKey = apiKey;
        this.logger.info('API key loaded from credential manager');
      } else {
        // Fall back to config file for backwards compatibility
        // This should only happen on first run before migration
        if (this.config.apiKey) {
          this.logger.warn('API key in config file - should migrate to credential manager');
        } else {
          this.logger.warn('No API key configured');
        }
      }

      // Check if HMAC is configured
      const hmacConfigured = await isHmacConfigured();
      if (hmacConfigured) {
        this.logger.info('HMAC verification enabled');
      } else {
        this.logger.warn('HMAC secret not configured - server messages will not be verified');
      }
    } catch (error) {
      this.logger.error('Error loading secure credentials', error);
    }
  }

  private log(message: string, error?: any): void {
    const timestamp = new Date().toISOString();
    const logMessage = `[${timestamp}] ${message}${error ? ` - ${error}` : ''}\n`;
    
    console.log(logMessage);
    
    try {
      const logFile = path.join(this.logsDir, 'agent.log');
      fs.appendFileSync(logFile, logMessage);
    } catch (err) {
      console.error('Failed to write log:', err);
    }
  }

  // ============================================
  // IPC SERVER HANDLERS
  // ============================================

  private broadcastTicketUpdate(): void {
    const tickets = this.ticketDb.getTickets(100);
    const stats = this.ticketDb.getStatistics();
    
    const guiStats = {
      issuesDetected: stats.totalTickets,
      issuesEscalated: stats.escalatedTickets,
      successRate: stats.successRate,
      activeTickets: stats.openTickets
    };
    
    this.ipcServer.broadcast({
      type: 'ticket-update',
      data: {
        tickets,
        stats: guiStats,
        healthScores: this.patternDetector.getHealthScores(),
        correlations: this.patternDetector.getCorrelations(),
        patterns: this.patternDetector.getDetectedPatterns(),
        proactiveActions: this.patternDetector.getPendingActions()
      }
    });
  }

  private setupIPCHandlers(): void {
    this.ipcServer.onMessage('get-tickets', (data, socket) => {
      this.logger.info('IPC: Received get-tickets request');
      const tickets = this.ticketDb.getTickets(100);
      const stats = this.ticketDb.getStatistics();
      
      const guiStats = {
        issuesDetected: stats.totalTickets,
        issuesEscalated: stats.escalatedTickets,
        successRate: stats.successRate,
        activeTickets: stats.openTickets
      };
      
      this.ipcServer.sendToClient(socket, {
        type: 'tickets',
        data: { tickets, stats: guiStats }
      });
    });

    this.ipcServer.onMessage('get-status', (data, socket) => {
      const stats = this.getSystemStats();
      this.ipcServer.sendToClient(socket, {
        type: 'status',
        data: stats
      });
    });

    this.ipcServer.onMessage('get-stats', (data, socket) => {
      this.logger.info('IPC: Received get-stats request');
      const tickets = this.ticketDb.getTickets(100);
      const ticketStats = this.ticketDb.getStatistics();
      
      const guiStats = {
        issuesDetected: ticketStats.totalTickets,
        issuesEscalated: ticketStats.escalatedTickets,
        successRate: ticketStats.successRate,
        activeTickets: ticketStats.openTickets
      };
      
      this.ipcServer.sendToClient(socket, {
        type: 'stats',
        data: guiStats
      });
    });

    this.ipcServer.onMessage('get-health-data', (data, socket) => {
      this.logger.info('IPC: Received get-health-data request');
      this.ipcServer.sendToClient(socket, {
        type: 'health-data',
        data: {
          healthScores: this.patternDetector.getHealthScores(),
          correlations: this.patternDetector.getCorrelations(),
          patterns: this.patternDetector.getDetectedPatterns(),
          proactiveActions: this.patternDetector.getPendingActions()
        }
      });
    });

    this.ipcServer.onMessage('get-ticket', (data, socket) => {
      const ticket = this.ticketDb.getTicket(data.ticketId);
      this.ipcServer.sendToClient(socket, {
        type: 'ticket-details',
        data: ticket
      });
    });
    
    this.ipcServer.onMessage('get-memory-stats', (data, socket) => {
      this.logger.info('IPC: Received get-memory-stats request');
      const summary = this.remediationMemory.getSummary();
      const memoryData = this.remediationMemory.exportData();
      
      this.ipcServer.sendToClient(socket, {
        type: 'memory-stats',
        data: {
          summary,
          dampenedSignals: Object.values(memoryData.signalStats).filter(s => s.dampened),
          topFailingPlaybooks: Object.values(memoryData.playbookStats)
            .filter(p => p.totalAttempts >= 3 && p.successRate < 0.5)
            .sort((a, b) => a.successRate - b.successRate)
            .slice(0, 10),
          deviceSensitivity: Object.values(memoryData.deviceSensitivity)
        }
      });
    });
    
    this.ipcServer.onMessage('reset-dampening', (data, socket) => {
      this.logger.info('IPC: Received reset-dampening request', data);
      this.remediationMemory.resetDampening(data.signalId, data.deviceId);
      this.ipcServer.sendToClient(socket, {
        type: 'dampening-reset',
        data: { success: true, signalId: data.signalId, deviceId: data.deviceId }
      });
    });
    
    this.ipcServer.onMessage('get-service-alerts', (data, socket) => {
      this.logger.info('IPC: Received get-service-alerts request');
      this.ipcServer.sendToClient(socket, {
        type: 'service-alerts',
        data: this.serviceAlerts
      });
    });

    this.ipcServer.onMessage('dismiss-alert', (data, socket) => {
      this.logger.info('IPC: Received dismiss-alert request', { alertId: data.alertId });
      this.serviceAlerts = this.serviceAlerts.filter(a => a.id !== data.alertId);
    });

    this.ipcServer.onMessage('update-config', (data, socket) => {
      this.updateConfig(data);
      this.ipcServer.sendToClient(socket, {
        type: 'config-updated',
        data: { success: true }
      });
    });
    
    this.ipcServer.onMessage('update-settings', (data, socket) => {
      this.logger.info('Received settings update from GUI', data);
      this.updateConfig(data);
      this.ipcServer.sendToClient(socket, {
        type: 'settings-updated',
        data: { success: true }
      });
    });

    this.ipcServer.onMessage('user-prompt-response', (data, socket) => {
      this.logger.info('Received user-prompt-response from GUI', data);
      const { promptId, response } = data;
      const pending = this.pendingPrompts.get(promptId);
      if (pending) {
        if (pending.timer) clearTimeout(pending.timer);
        this.pendingPrompts.delete(promptId);

        // If user confirmed and there's an action
        if (response === 'ok' && pending.action_on_confirm === 'reboot') {
          this.logger.info('User confirmed reboot, scheduling restart in 30 seconds');
          const { exec } = require('child_process');
          exec('shutdown /r /t 30 /c "OPSIS Agent: Restarting to complete remediation"', (err: any) => {
            if (err) this.logger.error('Failed to initiate reboot', err);
          });
        }

        // Resolve the promise
        pending.resolve(response);

        // Report back to server
        if (this.ws && this.ws.readyState === 1) {
          this.ws.send(JSON.stringify({
            type: 'user-prompt-response',
            prompt_id: promptId,
            response,
            device_id: this.deviceInfo.device_id,
            timestamp: new Date().toISOString()
          }));
        }
      } else {
        this.logger.warn('No pending prompt found for id', { promptId });
      }
    });

    // Service suppression handlers for GUI
    this.ipcServer.onMessage('suppress-service', async (data, socket) => {
      const { serviceName } = data;
      this.logger.info('IPC: Received suppress-service request', { serviceName });

      // Check if service is safe to stop
      if (!OPSISAgentService.SAFE_TO_STOP_SERVICES.has(serviceName)) {
        this.ipcServer.sendToClient(socket, {
          type: 'suppress-service-result',
          data: { success: false, error: `Service '${serviceName}' is not safe to stop` }
        });
        return;
      }

      try {
        // Stop the service
        await execAsync(`powershell -NoProfile -Command "Stop-Service -Name '${serviceName}' -Force"`, { timeout: 30000 });

        // Add to suppressed list
        this.suppressedServices.add(serviceName);
        this.logger.info('Service suppressed', { serviceName, suppressedCount: this.suppressedServices.size });

        this.ipcServer.sendToClient(socket, {
          type: 'suppress-service-result',
          data: { success: true, serviceName, status: 'stopped_and_suppressed' }
        });
      } catch (error: any) {
        this.logger.error('Failed to suppress service', { serviceName, error: error.message });
        this.ipcServer.sendToClient(socket, {
          type: 'suppress-service-result',
          data: { success: false, error: error.message }
        });
      }
    });

    this.ipcServer.onMessage('unsuppress-service', async (data, socket) => {
      const { serviceName, startService } = data;
      this.logger.info('IPC: Received unsuppress-service request', { serviceName, startService });

      this.suppressedServices.delete(serviceName);

      if (startService) {
        try {
          await execAsync(`powershell -NoProfile -Command "Start-Service -Name '${serviceName}'"`, { timeout: 30000 });
          this.ipcServer.sendToClient(socket, {
            type: 'unsuppress-service-result',
            data: { success: true, serviceName, status: 'unsuppressed_and_started' }
          });
        } catch (error: any) {
          this.ipcServer.sendToClient(socket, {
            type: 'unsuppress-service-result',
            data: { success: true, serviceName, status: 'unsuppressed_but_start_failed', error: error.message }
          });
        }
      } else {
        this.ipcServer.sendToClient(socket, {
          type: 'unsuppress-service-result',
          data: { success: true, serviceName, status: 'unsuppressed' }
        });
      }
    });

    this.ipcServer.onMessage('get-suppressed-services', (data, socket) => {
      this.logger.info('IPC: Received get-suppressed-services request');
      this.ipcServer.sendToClient(socket, {
        type: 'suppressed-services',
        data: {
          services: Array.from(this.suppressedServices),
          safeServices: Array.from(OPSISAgentService.SAFE_TO_STOP_SERVICES)
        }
      });
    });

    // Pending actions handlers
    this.ipcServer.onMessage('get-pending-actions', (data, socket) => {
      this.logger.info('IPC: Received get-pending-actions request');
      const actions = Array.from(this.pendingActions.entries()).map(([id, action]) => ({
        signature_id: id,
        ticket_id: action.ticket_id,
        runbook_name: action.runbook?.name,
        server_message: action.server_message,
        created_at: action.created_at,
        signature_name: action.signature.signature_id, // Use signature_id as name
        severity: action.signature.severity
      }));
      this.ipcServer.sendToClient(socket, {
        type: 'pending-actions',
        data: { actions }
      });
    });

    this.ipcServer.onMessage('execute-pending-action', (data, socket) => {
      const { signature_id } = data;
      this.logger.info('IPC: Received execute-pending-action request', { signature_id });
      if (signature_id && this.pendingActions.has(signature_id)) {
        this.executePendingAction(signature_id);
        this.ipcServer.sendToClient(socket, {
          type: 'execute-pending-action-result',
          data: { success: true, signature_id }
        });
      } else {
        this.ipcServer.sendToClient(socket, {
          type: 'execute-pending-action-result',
          data: { success: false, signature_id, error: 'Pending action not found' }
        });
      }
    });

    this.ipcServer.onMessage('cancel-pending-action', (data, socket) => {
      const { signature_id, reason } = data;
      this.logger.info('IPC: Received cancel-pending-action request', { signature_id, reason });
      if (signature_id && this.pendingActions.has(signature_id)) {
        this.cancelPendingAction(signature_id, reason);
        this.ipcServer.sendToClient(socket, {
          type: 'cancel-pending-action-result',
          data: { success: true, signature_id }
        });
      } else {
        this.ipcServer.sendToClient(socket, {
          type: 'cancel-pending-action-result',
          data: { success: false, signature_id, error: 'Pending action not found' }
        });
      }
    });

    // Handle manual ticket submission from GUI
    this.ipcServer.onMessage('submit-manual-ticket', (data, socket) => {
      this.logger.info('IPC: Received submit-manual-ticket request', data);
      try {
        const ticketId = `manual-${Date.now()}`;
        const ticket = {
          ticket_id: ticketId,
          timestamp: data.submittedAt || new Date().toISOString(),
          type: 'manual-investigation',
          description: `[${data.category}] ${data.description} (Server: ${data.serverName}, Priority: ${data.priority})`,
          status: 'open' as const,
          source: 'manual' as const,
          computer_name: data.serverName || os.hostname(),
          escalated: 1
        };

        this.ticketDb.createTicket(ticket);
        this.ticketDb.markAsEscalated(ticketId);

        this.logger.info('Manual ticket created', { ticketId, category: data.category });

        // Broadcast update to all GUI clients
        this.broadcastTicketUpdate();

        this.ipcServer.sendToClient(socket, {
          type: 'submit-manual-ticket-result',
          data: { success: true, ticketId }
        });
      } catch (error) {
        this.logger.error('Failed to create manual ticket', error);
        this.ipcServer.sendToClient(socket, {
          type: 'submit-manual-ticket-result',
          data: { success: false, error: (error as Error).message }
        });
      }
    });

    // Test escalation handler - creates a fake issue to test server response
    this.ipcServer.onMessage('test-escalation', async (data, socket) => {
      this.logger.info('IPC: Received test-escalation request', data);

      const issueType = data.type || 'disk-space-low';
      const testSignature: DeviceSignature = {
        signature_id: `test-${Date.now()}-${Math.random().toString(36).substring(7)}`,
        tenant_id: this.deviceInfo.tenant_id,
        device_id: this.deviceInfo.device_id,
        timestamp: new Date().toISOString(),
        severity: data.severity || 'medium',
        confidence_local: data.confidence || 65,
        symptoms: [],
        targets: [],
        context: {
          os_build: os.release(),
          os_version: `Windows ${os.release()}`,
          device_role: this.deviceInfo.role || 'workstation'
        }
      };

      // Configure symptoms based on issue type
      switch (issueType) {
        case 'disk-space-low':
          testSignature.symptoms = [{
            type: 'disk',
            severity: 'high',
            details: { drive: 'C:', free_percent: 5, threshold: 10 }
          }];
          testSignature.targets = [{ type: 'system', name: 'C:', identifier: 'C:' }];
          break;
        case 'high-cpu':
          testSignature.symptoms = [{
            type: 'performance',
            severity: 'high',
            details: { metric: 'cpu_usage', value: 95, threshold: 90 }
          }];
          testSignature.targets = [{ type: 'system', name: 'CPU', identifier: 'processor' }];
          break;
        case 'service-stopped':
          testSignature.symptoms = [{
            type: 'service_status',
            severity: 'high',
            details: { service: data.service || 'TestService', state: 'Stopped', expected: 'Running' }
          }];
          testSignature.targets = [{ type: 'service', name: data.service || 'TestService' }];
          break;
        case 'high-memory':
          testSignature.symptoms = [{
            type: 'performance',
            severity: 'high',
            details: { metric: 'memory_usage', value: 92, threshold: 85 }
          }];
          testSignature.targets = [{ type: 'system', name: 'Memory', identifier: 'ram' }];
          break;
        default:
          testSignature.symptoms = [{
            type: 'performance',
            severity: 'medium',
            details: { description: data.description || 'Test issue for server processing' }
          }];
          testSignature.targets = [{ type: 'system', name: 'Test', identifier: 'test' }];
      }

      this.logger.info('Creating test escalation', {
        signature_id: testSignature.signature_id,
        type: issueType,
        symptoms: testSignature.symptoms
      });

      // Escalate to server
      this.escalateToServer(testSignature, null);

      this.ipcServer.sendToClient(socket, {
        type: 'test-escalation-result',
        data: {
          success: true,
          signature_id: testSignature.signature_id,
          issue_type: issueType,
          message: 'Test escalation sent to server'
        }
      });
    });

    // Maintenance window IPC handlers
    this.ipcServer.onMessage('create-maintenance-window', (data, socket) => {
      const window: MaintenanceWindow = {
        id: `mw-gui-${Date.now()}`,
        name: data.name || 'Maintenance Window',
        startTime: data.startTime || new Date().toISOString(),
        endTime: data.endTime,
        scope: data.scope || { type: 'all' },
        suppressEscalation: data.suppressEscalation !== false,
        suppressRemediation: data.suppressRemediation !== false,
        createdBy: 'technician',
        createdAt: new Date().toISOString()
      };
      this.maintenanceManager.addWindow(window);

      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({ type: 'maintenance_window_created', data: window }));
      }

      this.ipcServer.sendToClient(socket, { type: 'maintenance-window-created', data: { success: true, window } });
    });

    this.ipcServer.onMessage('cancel-maintenance-window', (data, socket) => {
      this.maintenanceManager.removeWindow(data.id);
      this.ipcServer.sendToClient(socket, { type: 'maintenance-window-cancelled', data: { success: true, id: data.id } });
    });

    this.ipcServer.onMessage('get-maintenance-windows', (data, socket) => {
      this.ipcServer.sendToClient(socket, {
        type: 'maintenance-windows',
        data: {
          all: this.maintenanceManager.getAllWindows(),
          active: this.maintenanceManager.getActiveWindows()
        }
      });
    });

    this.ipcServer.onMessage('get-state-tracker-summary', (data, socket) => {
      this.ipcServer.sendToClient(socket, {
        type: 'state-tracker-summary',
        data: this.stateTracker.getSummary()
      });
    });
  }

  // ============================================
  // LIFECYCLE
  // ============================================

  /**
   * Detect OS-level policy restrictions that may block agent operations.
   * Logs warnings so operators know what won't work on this endpoint.
   */
  private async detectPolicyRestrictions(): Promise<void> {
    this.logger.info('Checking endpoint policy restrictions...');

    // 1. Check PowerShell execution policy
    try {
      const { stdout } = await execAsync(
        'powershell -Command "Get-ExecutionPolicy"',
        { timeout: 10000 }
      );
      const policy = stdout.trim();
      if (policy === 'Restricted' || policy === 'AllSigned') {
        this.logger.warn('PowerShell execution policy may block scripts', { policy });
      } else {
        this.logger.info('PowerShell execution policy', { policy });
      }
    } catch {
      this.logger.warn('Cannot determine PowerShell execution policy');
    }

    // 2. Check if AppLocker is active
    try {
      const { stdout } = await execAsync(
        'powershell -Command "(Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue).RuleCollections.Count"',
        { timeout: 10000 }
      );
      const ruleCount = parseInt(stdout.trim() || '0');
      if (ruleCount > 0) {
        this.logger.warn('AppLocker is active with rules — some operations may be blocked', { ruleCount });
      }
    } catch {
      // AppLocker cmdlets not available — likely not enforced
    }

    // 3. Check Windows Defender Tamper Protection
    try {
      const { stdout } = await execAsync(
        'powershell -Command "(Get-MpComputerStatus).IsTamperProtected"',
        { timeout: 10000 }
      );
      if (stdout.trim() === 'True') {
        this.logger.info('Defender Tamper Protection is enabled (security settings cannot be modified by agent)');
      }
    } catch {
      // Defender not available or insufficient permissions
    }

    // 4. Check if Defender exclusion is in place for this directory
    try {
      const { stdout } = await execAsync(
        `powershell -Command "(Get-MpPreference).ExclusionPath -contains '${this.baseDir}'  "`,
        { timeout: 10000 }
      );
      if (stdout.trim() !== 'True') {
        this.logger.warn('Agent install directory is NOT excluded from Defender — PowerShell operations may be flagged');
      }
    } catch {
      // Non-fatal
    }

    // 5. Check if running as SYSTEM / elevated
    try {
      const { stdout } = await execAsync(
        'powershell -Command "[System.Security.Principal.WindowsIdentity]::GetCurrent().Name"',
        { timeout: 10000 }
      );
      const identity = stdout.trim();
      this.logger.info('Service running as', { identity });
      if (!identity.includes('SYSTEM') && !identity.includes('Administrator')) {
        this.logger.warn('Agent is NOT running as SYSTEM or Administrator — some operations will fail');
      }
    } catch {
      this.logger.warn('Cannot determine service identity');
    }

    this.logger.info('Policy restriction check complete');
  }

  public async start(): Promise<void> {
    this.log('OPSIS Agent Service Starting...');

    // Load credentials from Windows Credential Manager (keytar)
    await this.loadSecureCredentials();

    // Check what this endpoint allows before starting operations
    await this.detectPolicyRestrictions();

    // Start IPC server for GUI (with authentication)
    await this.ipcServer.start();
    this.log('IPC server started');

    // Load pending actions from disk
    this.loadPendingActions();

    // Launch GUI console in user session
    this.guiLauncher.launchGui();

    // Start event monitoring
    this.eventMonitor.startMonitoring(30);
    this.log('Event monitoring started');

    // Start system monitoring
    this.systemMonitor.start();
    this.log('System monitoring started (60 second intervals)');

    // Initialize baseline health scores for hardware components
    await this.patternDetector.initializeBaselineHealthScores();
    this.log('Hardware health scores initialized');

    // Connect to server if configured
    const serverUrl = this.deviceInfo.websocket_url || this.config.serverUrl;
    if (serverUrl && this.config.autoConnect) {
      await this.connectToServer();
    }

    // Start update checker
    if (this.config.autoUpdate) {
      this.startUpdateChecker();
    }
    
    // Start pattern analysis
    this.startPatternAnalysis();

    // Process playbook queue
    this.processPlaybookQueue();

    // Start monitoring trap agent features
    this.stateTracker.refreshDependencyMap().catch(err =>
      this.logger.warn('Initial dependency map refresh failed', err)
    );
    this.dependencyRefreshTimer = setInterval(() => {
      this.stateTracker.refreshDependencyMap().catch(err =>
        this.logger.warn('Dependency map refresh failed', err)
      );
    }, 5 * 60 * 1000);

    this.severityEscalationTimer = setInterval(() => {
      this.checkSeverityEscalations();
      const stableResources = this.stateTracker.checkFlapStability();
      for (const resourceId of stableResources) {
        this.stateTracker.clearState(resourceId);
      }
    }, 60000);

    this.maintenanceManager.startExpirationChecks();
    this.maintenanceManager.onExpiration((window) => {
      this.logger.info('Maintenance window expired, forcing re-evaluation', { id: window.id, name: window.name });
      if (window.scope.type === 'services' && window.scope.services) {
        for (const svc of window.scope.services) {
          this.stateTracker.clearState(`service:${svc}`);
        }
      } else if (window.scope.type === 'all') {
        this.stateTracker.clearAllStates();
      }
    });

    // Start real-time event subscriptions
    try {
      this.eventMonitor.startEventSubscriptions();
      this.log('Real-time event subscriptions started');
    } catch (err) {
      this.logger.warn('Failed to start event subscriptions, polling fallback active', err);
    }

    this.log('OPSIS Agent Service Started Successfully');
  }

  public stop(): void {
    this.log('OPSIS Agent Service Stopping...');

    // Kill GUI before stopping IPC
    if (this.guiLauncher) {
      this.guiLauncher.killGui();
    }

    if (this.ipcServer) {
      this.ipcServer.stop();
    }

    if (this.eventMonitor) {
      this.eventMonitor.stopMonitoring();
    }

    if (this.systemMonitor) {
      this.systemMonitor.stop();
    }

    if (this.ticketDb) {
      this.ticketDb.close();
    }

    if (this.ws) {
      this.ws.close();
    }

    if (this.updateCheckTimer) {
      clearInterval(this.updateCheckTimer);
    }

    if (this.batchTimer) {
      clearTimeout(this.batchTimer);
      this.flushEscalationBatch(); // Send any pending batch before shutdown
    }

    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
    }

    if (this.telemetryTimer) {
      clearInterval(this.telemetryTimer);
    }

    if (this.severityEscalationTimer) {
      clearInterval(this.severityEscalationTimer);
    }

    if (this.dependencyRefreshTimer) {
      clearInterval(this.dependencyRefreshTimer);
    }

    if (this.maintenanceManager) {
      this.maintenanceManager.stopExpirationChecks();
    }

    this.log('OPSIS Agent Service Stopped');
  }

  // ============================================
  // SERVER CONNECTION (UPDATED WITH TIERED INTELLIGENCE)
  // ============================================

  private async connectToServer(): Promise<void> {
    if (!this.sessionValid) {
      this.logger.warn('Session invalidated, not reconnecting. Check API key / billing.');
      return;
    }

    let wsUrl = this.deviceInfo.websocket_url || null;
    if (!wsUrl && this.config.serverUrl) {
      let base = this.config.serverUrl;
      // Normalize to ws:// URL
      if (base.startsWith('http')) {
        base = base.replace(/^http/, 'ws');
      } else if (!base.startsWith('ws')) {
        base = 'ws://' + base;
      }
      wsUrl = base.replace(/\/$/, '') + '/api/agent/ws/' + this.deviceInfo.device_id;
    }

    this.logger.debug('Connection attempt', { wsUrl, attempt: this.reconnectAttempts });

    if (!wsUrl) {
      this.log('No WebSocket URL configured');
      return;
    }

    try {
      this.log(`Connecting to OPSIS server: ${wsUrl}`);

      const headers: Record<string, string> = {
        'X-Agent-Version': '1.0.0',
        'X-Agent-Machine': os.hostname(),
        'X-Agent-OS': `${os.platform()} ${os.release()}`
      };

      // Auth via API key (server derives tenant from key)
      if (this.config.apiKey) {
        headers['Authorization'] = `Bearer ${this.config.apiKey}`;
      }

      this.ws = new WebSocket(wsUrl, { headers });

      this.ws.on('open', () => {
        this.log('Connected to OPSIS server, sending registration...');
        this.reconnectAttempts = 0; // Reset backoff on successful connection

        // Send registration immediately — don't wait for welcome
        this.ws!.send(JSON.stringify({
          type: 'register',
          device_id: this.deviceInfo.device_id,
          tenant_id: this.deviceInfo.tenant_id,
          hostname: os.hostname(),
          agent_version: '1.0.0',
          os: `${os.platform()} ${os.release()}`,
          timestamp: new Date().toISOString()
        }));

        // Start heartbeat immediately with default interval
        // (will be updated if welcome arrives with custom config)
        if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
        this.sendHeartbeat();
        this.heartbeatTimer = setInterval(() => this.sendHeartbeat(), 30000);

        // Warn if server doesn't send welcome within 10s
        if (this.welcomeTimeout) clearTimeout(this.welcomeTimeout);
        this.welcomeTimeout = setTimeout(() => {
          this.logger.warn('No welcome received from server within 10s — continuing without server config');
          this.welcomeTimeout = null;
        }, 10000);

        this.log('Registration sent, heartbeat started');
      });

      this.ws.on('message', (data: WebSocket.Data) => {
        this.handleServerMessage(data.toString());
      });

      this.ws.on('error', (error) => {
        this.log('WebSocket error', error);
      });

      this.ws.on('close', (code) => {
        this.log(`Disconnected from server (code: ${code}), will retry with backoff...`);
        this.scheduleReconnect();
      });

    } catch (error) {
      this.log('Failed to connect to server', error);
      this.scheduleReconnect();
    }
  }

  private scheduleReconnect(): void {
    if (!this.sessionValid) return;

    // Exponential backoff with jitter: base * 2^attempt + random jitter, capped
    const exponentialDelay = Math.min(
      this.RECONNECT_BASE_MS * Math.pow(2, this.reconnectAttempts),
      this.RECONNECT_MAX_MS
    );
    const jitter = Math.random() * exponentialDelay * 0.3;
    const delay = Math.floor(exponentialDelay + jitter);

    this.reconnectAttempts++;
    this.logger.info('Scheduling reconnect', { attempt: this.reconnectAttempts, delayMs: delay });
    setTimeout(() => this.connectToServer(), delay);
  }

  private sendTelemetry(signal: SystemSignal): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({
        type: 'telemetry',
        timestamp: new Date().toISOString(),
        device_id: this.deviceInfo.device_id,
        tenant_id: this.deviceInfo.tenant_id,
        signal: {
          id: signal.id,
          category: signal.category,
          severity: signal.severity,
          metric: signal.metric,
          value: signal.value,
          threshold: signal.threshold,
          message: signal.message,
          metadata: signal.metadata
        }
      }));
    }
  }

  private sendHeartbeat(): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({
        type: 'heartbeat',
        timestamp: new Date().toISOString(),
        data: {
          status: 'online',
          stats: this.getSystemStats(),
          healthScores: this.patternDetector.getHealthScores()
        }
      }));
    }
  }

  // UPDATED: Handle server messages including decisions
  private handleServerMessage(message: string): void {
    // SECURITY: Use safe JSON parsing
    const { parsed: data, error: parseError } = tryParseJSON(message);
    if (parseError || !data) {
      this.logger.error('Failed to parse server message', { error: parseError });
      return;
    }

    try {
      this.logger.info('Received server message', { type: data.type });

      switch (data.type) {
        case 'welcome':
          this.handleWelcome(data);
          break;

        case 'pong':
          // Heartbeat acknowledgment
          this.logger.debug('Heartbeat acknowledged');
          break;

        case 'ack':
          // Message acknowledged
          break;
          
        case 'decision':
          // NEW: Server decision for escalation
          this.handleServerDecision(data.data);
          break;
          
        case 'playbook':
          this.receivePlaybook(data.playbook, 'server');
          break;
          
        case 'execute_playbook':
          // Server requested playbook execution
          this.logger.info('Server requested playbook execution', {
            playbook_id: data.data.playbook_id
          });
          break;
          
        case 'update-available':
          this.handleUpdateAvailable(data.version, data.downloadUrl);
          break;
          
        case 'force-diagnostic':
          this.runDiagnostic(data.scenario);
          break;

        case 'diagnostic_request':
          this.logger.info('Received diagnostic_request', { session_id: data.data?.session_id });
          // SECURITY: Verify HMAC and validate before executing
          this.handleSecureDiagnosticRequest(data.data || data);
          break;

        case 'key_rotation':
          // SECURITY: Handle key rotation from server
          this.handleKeyRotationMessage(data);
          break;

        case 'diagnostic_complete':
          this.handleDiagnosticComplete(data);
          break;

        case 'add_to_ignore_list':
          this.handleAddToIgnoreList(data);
          break;

        case 'reinvestigation_response':
          this.handleReinvestigationResponse(data.data || data);
          break;

        case 'config-update':
          this.updateConfig(data.config);
          break;

        case 'session_expired':
        case 'auth_failed':
        case 'billing_expired':
          this.logger.error('Session terminated by server', { reason: data.type, message: data.message });
          this.sessionValid = false;
          if (this.ws) {
            this.ws.close();
            this.ws = null;
          }
          break;

        case 'service-alert':
          this.handleServiceAlert(data.data);
          break;

        case 'service-alert-resolved':
          this.handleServiceAlertResolved(data.data);
          break;

        case 'advisory':
          // Log full advisory payload for debugging
          this.logger.info('Received advisory from server', {
            message: data.message,
            data: data.data,
            raw: JSON.stringify(data)
          });
          // Server advisory response (e.g. for Class C escalations)
          if (data.data && data.data.decision_type) {
            this.handleServerDecision(data.data);
          } else {
            // Server sent a simple advisory (e.g. "Creating ticket for review")
            // Check if there's a pending escalation with a matched runbook to execute
            this.handleAdvisoryWithPendingRunbook(data.message);
          }
          break;

        case 'ticket_created':
          // Server created a ticket for manual review
          this.logger.info('Received ticket_created from server', {
            ticket_id: data.ticket_id,
            message: data.message,
            raw: JSON.stringify(data)
          });
          // Treat this as a "manual review required" advisory
          this.handleAdvisoryWithPendingRunbook(data.message || 'Issue requires manual review');
          break;

        case 'user-prompt':
          this.handleUserPrompt(data.data || data);
          break;

        case 'execute_pending_action':
          // Server/technician approved a pending action
          this.logger.info('Received execute_pending_action from server', {
            signature_id: data.signature_id || data.data?.signature_id
          });
          const execSigId = data.signature_id || data.data?.signature_id;
          if (execSigId) {
            this.executePendingAction(execSigId);
          }
          break;

        case 'cancel_pending_action':
          // Server/technician cancelled a pending action
          this.logger.info('Received cancel_pending_action from server', {
            signature_id: data.signature_id || data.data?.signature_id,
            reason: data.reason || data.data?.reason
          });
          const cancelSigId = data.signature_id || data.data?.signature_id;
          if (cancelSigId) {
            this.cancelPendingAction(cancelSigId, data.reason || data.data?.reason);
          }
          break;

        case 'maintenance_window':
          this.handleMaintenanceWindowMessage(data.data || data);
          break;

        case 'cancel_maintenance_window':
          this.handleCancelMaintenanceWindow(data.data || data);
          break;

        default:
          this.logger.warn('Unknown message type', { type: data.type, raw: JSON.stringify(data) });
      }
    } catch (error) {
      this.log('Error handling server message', error);
    }
  }

  // Handle service outage/issue alerts from server (M365, Google Apps, etc.)
  private handleServiceAlert(alert: any): void {
    if (!alert || !alert.id) {
      this.logger.warn('Received invalid service alert (missing id)');
      return;
    }

    this.logger.info('Service alert received', {
      id: alert.id,
      service: alert.service,
      severity: alert.severity
    });

    // Replace existing alert with same id, or add new
    const idx = this.serviceAlerts.findIndex(a => a.id === alert.id);
    if (idx >= 0) {
      this.serviceAlerts[idx] = alert;
    } else {
      this.serviceAlerts.push(alert);
    }

    // Broadcast to all connected GUI clients
    this.ipcServer.broadcast({
      type: 'service-alert',
      data: alert
    });
  }

  // Handle service alert resolution
  private handleServiceAlertResolved(data: any): void {
    const alertId = data?.id || data?.alertId;
    if (!alertId) return;

    this.logger.info('Service alert resolved', { id: alertId });
    this.serviceAlerts = this.serviceAlerts.filter(a => a.id !== alertId);

    this.ipcServer.broadcast({
      type: 'service-alert-resolved',
      data: { id: alertId }
    });
  }

  /**
   * Handle a user-prompt message from the server.
   * Broadcasts to GUI and waits for user response.
   */
  private handleUserPrompt(promptData: any): void {
    const promptId = promptData.id || `prompt-${Date.now()}`;
    const timeout = (promptData.timeout || 300) * 1000; // default 5 minutes

    this.logger.info('User prompt received', {
      id: promptId,
      title: promptData.title,
      action_on_confirm: promptData.action_on_confirm
    });

    // Create promise for response tracking (fire-and-forget, response handled by IPC)
    const timer = setTimeout(() => {
      this.logger.info('User prompt timed out, auto-declining', { promptId });
      const pending = this.pendingPrompts.get(promptId);
      if (pending) {
        this.pendingPrompts.delete(promptId);
        pending.resolve('timeout');
      }

      // Notify server of timeout
      if (this.ws && this.ws.readyState === 1) {
        this.ws.send(JSON.stringify({
          type: 'user-prompt-response',
          prompt_id: promptId,
          response: 'timeout',
          device_id: this.deviceInfo.device_id,
          timestamp: new Date().toISOString()
        }));
      }
    }, timeout);

    this.pendingPrompts.set(promptId, {
      resolve: () => {}, // Server-initiated prompts don't block execution
      action_on_confirm: promptData.action_on_confirm,
      timer
    });

    // Broadcast to GUI
    this.ipcServer.broadcast({
      type: 'user-prompt',
      data: {
        id: promptId,
        title: promptData.title || 'Action Required',
        message: promptData.message || '',
        buttons: promptData.buttons || ['OK', 'Cancel'],
        action_on_confirm: promptData.action_on_confirm,
        timeout: promptData.timeout || 300
      }
    });
  }

  /**
   * Execute a reboot playbook step - prompts user then reboots if confirmed.
   */
  private async executeReboot(params: Record<string, any>): Promise<void> {
    // SECURITY: Validate delay as integer to prevent command injection
    let delay = 30;
    if (params.delay !== undefined) {
      const parsedDelay = parseInt(String(params.delay), 10);
      if (isNaN(parsedDelay) || parsedDelay < 0 || parsedDelay > 3600) {
        this.logger.error('Invalid reboot delay parameter', { delay: params.delay });
        throw new Error('Invalid delay parameter: must be integer 0-3600');
      }
      delay = parsedDelay;
    }
    // SECURITY: Sanitize message - remove shell metacharacters
    const rawMessage = params.message || 'Please save your work. The computer needs to restart to complete a resolution.';
    const message = String(rawMessage).replace(/[`$&|;<>\r\n"]/g, '');
    const promptId = `reboot-${Date.now()}`;

    this.logger.info('Reboot step: prompting user for confirmation');

    const response = await new Promise<string>((resolve) => {
      const timer = setTimeout(() => {
        this.logger.info('Reboot prompt timed out, skipping reboot');
        this.pendingPrompts.delete(promptId);
        resolve('timeout');
      }, 300000); // 5 minute timeout

      this.pendingPrompts.set(promptId, {
        resolve,
        action_on_confirm: 'reboot',
        timer
      });

      this.ipcServer.broadcast({
        type: 'user-prompt',
        data: {
          id: promptId,
          title: 'Restart Required',
          message,
          buttons: ['Restart Now', 'Later'],
          action_on_confirm: 'reboot',
          timeout: 300
        }
      });
    });

    if (response === 'ok') {
      this.logger.info(`User confirmed reboot, scheduling in ${delay} seconds`);
      const { spawnSync } = require('child_process');
      // SECURITY: Use spawnSync with array args to prevent command injection
      const result = spawnSync('shutdown.exe', [
        '/r',
        '/t', String(delay),
        '/c', 'OPSIS Agent: Restarting to complete remediation'
      ], { timeout: 10000 });
      if (result.error) {
        this.logger.error('Failed to initiate reboot', result.error);
      }
    } else {
      this.logger.info('User declined or timed out on reboot prompt', { response });
    }
  }

  /**
   * Execute a user-prompt playbook step - shows message and waits for response.
   */
  private async executeUserPrompt(action: string, params: Record<string, any>): Promise<void> {
    const promptId = `step-prompt-${Date.now()}`;
    const timeout = params.timeout || 300;

    this.logger.info('User-prompt step: showing prompt to user', { action });

    const response = await new Promise<string>((resolve) => {
      const timer = setTimeout(() => {
        this.pendingPrompts.delete(promptId);
        resolve('timeout');
      }, timeout * 1000);

      this.pendingPrompts.set(promptId, {
        resolve,
        action_on_confirm: params.action_on_confirm,
        timer
      });

      this.ipcServer.broadcast({
        type: 'user-prompt',
        data: {
          id: promptId,
          title: params.title || 'Action Required',
          message: action,
          buttons: params.buttons || ['OK', 'Cancel'],
          action_on_confirm: params.action_on_confirm,
          timeout
        }
      });
    });

    this.logger.info('User-prompt step response', { promptId, response });
  }

  // NEW METHOD: Handle Server Decision
  private handleServerDecision(decision: ServerDecision): void {
    // Validate decision fields
    const validTypes = ['execute_A', 'execute_B', 'request_approval', 'advisory_only', 'block', 'ignore'];
    if (!validTypes.includes(decision.decision_type)) {
      this.logger.error('Invalid decision_type from server', { decision_type: decision.decision_type });
      return;
    }
    if (typeof decision.confidence_server !== 'number' || decision.confidence_server < 0 || decision.confidence_server > 100) {
      this.logger.error('Invalid confidence_server from server', { confidence_server: decision.confidence_server });
      return;
    }

    this.logger.info('Received server decision', {
      decision_type: decision.decision_type,
      confidence: decision.confidence_server,
      requires_approval: decision.requires_approval
    });

    if (decision.decision_type === 'execute_A') {
      // Server approved auto-execution (Class A)
      this.logger.info('Server approved Class A auto-execution', {
        playbook_id: decision.recommended_playbook_id,
        confidence: decision.confidence_server
      });
      
      if (decision.recommended_playbook_id) {
        const classified = this.runbookClassifier.getRunbook(decision.recommended_playbook_id);
        if (classified) {
          const runbookMatch: RunbookMatch = {
            runbookId: classified.id,
            name: classified.name,
            confidence: decision.confidence_server / 100,
            trigger: 'server-decision',
            steps: classified.steps
          };
          const sig = this.pendingEscalations.values().next().value as DeviceSignature | undefined;
          if (sig) {
            this.executeLocalRemediation(sig, runbookMatch);
          } else {
            this.logger.warn('No pending signature found for Class A execution');
          }
        } else {
          this.logger.warn('Recommended playbook not found locally', {
            playbook_id: decision.recommended_playbook_id
          });
        }
      }
      
    } else if (decision.decision_type === 'execute_B') {
      // Class B - needs approval token
      this.logger.info('Server decision: Class B - requires approval', {
        approval_token: decision.approval_token
      });
      
      // Create manual ticket with approval info
      // TODO: Implement approval workflow
      
    } else if (decision.decision_type === 'request_approval') {
      // Needs human approval
      this.logger.info('Server decision: Human approval required');
      
    } else if (decision.decision_type === 'advisory_only') {
      // Server recommends human review
      this.logger.info('Server decision: Advisory only - human review recommended');
      
    } else if (decision.decision_type === 'block') {
      // Server blocked the action
      this.logger.warn('Server blocked action');

    } else if (decision.decision_type === 'ignore') {
      // Server says this should be ignored — add to exclusion list and close ticket
      this.handleIgnoreDecision(decision);
    }
  }

  // Handle simple advisory messages by checking for pending escalations with matched runbooks
  private handleAdvisoryWithPendingRunbook(message?: string): void {
    // Check if this is a "ticket for review" or "manual review" advisory - don't auto-execute
    const isCreateTicketReview = message && (
      message.toLowerCase().includes('creating ticket for review') ||
      message.toLowerCase().includes('ticket for review') ||
      message.toLowerCase().includes('awaiting review') ||
      message.toLowerCase().includes('pending review') ||
      message.toLowerCase().includes('requires manual review') ||
      message.toLowerCase().includes('manual review')
    );

    // Find the most recent pending escalation that has a matched runbook
    for (const [sigId, sig] of this.pendingEscalations.entries()) {
      const runbook = this.pendingRunbooks.get(sigId);

      // If server says "creating ticket for review", store as pending action instead of executing
      if (isCreateTicketReview) {
        this.logger.info('Advisory received - creating pending action for technician review', {
          signature_id: sigId,
          runbook_id: runbook?.runbookId,
          runbook_name: runbook?.name,
          server_message: message
        });

        this.createPendingAction(sigId, sig, runbook || null, message || 'Awaiting technician review');

        // Clean up pending state
        this.pendingEscalations.delete(sigId);
        if (runbook) this.pendingRunbooks.delete(sigId);
        return;
      }

      // Normal flow: execute the runbook if we have one
      if (!runbook) continue;

      this.logger.info('Advisory received - executing pending runbook for escalation', {
        signature_id: sigId,
        runbook_id: runbook.runbookId,
        runbook_name: runbook.name,
        server_message: message
      });

      // Clean up pending state
      this.pendingEscalations.delete(sigId);
      this.pendingRunbooks.delete(sigId);

      // Execute the matched runbook
      this.executeLocalRemediation(sig, runbook);
      return;
    }

    this.logger.debug('Advisory received but no pending runbook to execute', { message });
  }

  // Create a pending action that awaits technician review
  private createPendingAction(
    signatureId: string,
    signature: DeviceSignature,
    runbook: RunbookMatch | null,
    serverMessage: string
  ): void {
    // Create a ticket for technician review
    // SECURITY: Use cryptographically secure random ID
    const ticketId = `pending-action-${Date.now()}-${crypto.randomBytes(6).toString('hex')}`;

    // Store the pending action
    const pendingAction = {
      signature_id: signatureId,
      signature,
      runbook,
      ticket_id: ticketId,
      created_at: new Date().toISOString(),
      server_message: serverMessage
    };

    this.pendingActions.set(signatureId, pendingAction);
    this.awaitingReviewSignals.add(signatureId);

    // Create a ticket in pending-review status
    this.ticketDb.createTicket({
      ticket_id: ticketId,
      timestamp: new Date().toISOString(),
      type: 'pending-action',
      description: `Pending action awaiting technician review: ${runbook?.name || signatureId}`,
      status: 'pending-review',
      source: 'server-advisory',
      computer_name: os.hostname(),
      escalated: 0,
      signature_id: signatureId,
      runbook_id: runbook?.runbookId,
      runbook_name: runbook?.name,
      server_message: serverMessage
    });

    this.logger.info('Created pending action awaiting technician review', {
      ticket_id: ticketId,
      signature_id: signatureId,
      runbook_name: runbook?.name,
      server_message: serverMessage
    });

    // Save pending actions to disk
    this.savePendingActions();

    // Notify GUI of new pending action
    this.ipcServer.broadcast({
      type: 'pending-action-created',
      data: {
        ticket_id: ticketId,
        signature_id: signatureId,
        runbook_name: runbook?.name,
        server_message: serverMessage,
        created_at: pendingAction.created_at
      }
    });
  }

  // Save pending actions to disk for persistence
  private savePendingActions(): void {
    try {
      const data = {
        pending_actions: Array.from(this.pendingActions.entries()).map(([id, action]) => ({
          ...action,
          signature: {
            signature_id: action.signature.signature_id,
            severity: action.signature.severity
          }
        })),
        awaiting_review: Array.from(this.awaitingReviewSignals)
      };
      fs.writeFileSync(this.pendingActionsPath, JSON.stringify(data, null, 2));
    } catch (error: any) {
      this.logger.error('Failed to save pending actions', { error: error.message });
    }
  }

  // Load pending actions from disk
  private loadPendingActions(): void {
    try {
      if (fs.existsSync(this.pendingActionsPath)) {
        const data = JSON.parse(fs.readFileSync(this.pendingActionsPath, 'utf-8'));
        if (data.awaiting_review) {
          data.awaiting_review.forEach((id: string) => this.awaitingReviewSignals.add(id));
        }
        this.logger.info('Loaded pending actions from disk', {
          awaiting_review_count: this.awaitingReviewSignals.size
        });
      }
    } catch (error: any) {
      this.logger.error('Failed to load pending actions', { error: error.message });
    }
  }

  // Execute a pending action (called by server or technician approval)
  private executePendingAction(signatureId: string): void {
    const pendingAction = this.pendingActions.get(signatureId);
    if (!pendingAction) {
      this.logger.warn('No pending action found for signature', { signature_id: signatureId });
      return;
    }

    this.logger.info('Executing pending action after approval', {
      signature_id: signatureId,
      ticket_id: pendingAction.ticket_id,
      runbook_name: pendingAction.runbook?.name
    });

    // Clean up pending state
    this.pendingActions.delete(signatureId);
    this.awaitingReviewSignals.delete(signatureId);
    this.savePendingActions();

    // Update ticket status
    this.ticketDb.updateTicketStatus(pendingAction.ticket_id, 'in-progress');

    // Execute the runbook if we have one
    if (pendingAction.runbook) {
      this.executeLocalRemediation(pendingAction.signature, pendingAction.runbook);
    } else {
      this.logger.info('No runbook associated with pending action - escalating to server', {
        signature_id: signatureId
      });
      this.escalateToServer(pendingAction.signature, null);
    }
  }

  // Cancel a pending action
  private cancelPendingAction(signatureId: string, reason?: string): void {
    const pendingAction = this.pendingActions.get(signatureId);
    if (!pendingAction) {
      this.logger.warn('No pending action found to cancel', { signature_id: signatureId });
      return;
    }

    this.logger.info('Cancelling pending action', {
      signature_id: signatureId,
      ticket_id: pendingAction.ticket_id,
      reason
    });

    // Clean up
    this.pendingActions.delete(signatureId);
    this.awaitingReviewSignals.delete(signatureId);
    this.savePendingActions();

    // Update ticket
    this.ticketDb.closeTicket(pendingAction.ticket_id, reason || 'Cancelled by technician', 'success');
  }

  // Check if a signal is awaiting technician review
  private isAwaitingReview(signatureId: string): boolean {
    return this.awaitingReviewSignals.has(signatureId);
  }

  private handleIgnoreDecision(decision: ServerDecision): void {
    const reason = decision.reason || 'Server AI determined this should be ignored';

    this.logger.info('Server decision: Add to ignore list', {
      reason,
      ignore_target: decision.ignore_target,
      ignore_category: decision.ignore_category,
      signature_id: decision.signature_id
    });

    // Determine what to exclude
    let target = decision.ignore_target;
    let category = decision.ignore_category;
    const signatureId = decision.signature_id;

    // If server provided a signature_id, try to infer target and category from it
    if (signatureId && !target) {
      const inferred = this.inferExclusionFromSignature(signatureId);
      target = inferred.target;
      category = inferred.category;
    }

    // Fall back to using signature_id itself as the exclusion target
    if (!target && signatureId) {
      target = signatureId;
      category = 'signatures';
    }

    if (target && category) {
      this.addToExclusionList(target, category);
    } else {
      this.logger.warn('Could not determine exclusion target from ignore decision', { decision });
    }

    // Find and close associated ticket(s)
    let ticketClosed = false;
    if (signatureId) {
      // Check pending escalations for matching signature
      const sig = this.pendingEscalations.get(signatureId);
      if (sig) {
        this.pendingEscalations.delete(signatureId);
      }

      // Find open tickets related to this signature and close them
      const tickets = this.ticketDb.getTickets();
      for (const ticket of tickets) {
        if (ticket.status !== 'resolved' &&
            ticket.description && ticket.description.includes(signatureId)) {
          this.ticketDb.closeTicket(ticket.ticket_id, reason, 'success');
          this.logger.info('Ticket resolved via ignore decision', {
            ticketId: ticket.ticket_id,
            reason
          });
          ticketClosed = true;
        }
      }
    }

    // If no specific ticket found, try to close the most recent open escalated ticket
    if (!ticketClosed) {
      const tickets = this.ticketDb.getTickets();
      const openEscalated = tickets.find(t =>
        t.status !== 'resolved' && t.escalated
      );
      if (openEscalated) {
        this.ticketDb.closeTicket(openEscalated.ticket_id, reason, 'success');
        this.logger.info('Ticket resolved via ignore decision (fallback)', {
          ticketId: openEscalated.ticket_id,
          reason
        });
      }
    }

    this.broadcastTicketUpdate();

    // Report back to server
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({
        type: 'action_result',
        timestamp: new Date().toISOString(),
        data: {
          decision_type: 'ignore',
          signature_id: signatureId,
          target,
          category,
          status: 'success',
          reason
        }
      }));
    }
  }

  private inferExclusionFromSignature(signatureId: string): { target: string; category: 'services' | 'processes' | 'signatures' } {
    // RULE_SERVICE_STOPPED_<serviceName> → services category
    const serviceMatch = signatureId.match(/^RULE_SERVICE_STOPPED_(.+)$/);
    if (serviceMatch) {
      return { target: serviceMatch[1], category: 'services' };
    }

    // Default: use the signature ID itself
    return { target: signatureId, category: 'signatures' };
  }

  private addToExclusionList(target: string, category: 'services' | 'processes' | 'signatures'): void {
    const configDir = path.join(process.cwd(), 'config');
    const exclusionsPath = path.join(configDir, 'exclusions.json');

    // Ensure config directory exists
    if (!fs.existsSync(configDir)) {
      fs.mkdirSync(configDir, { recursive: true });
    }

    // Load existing exclusions
    let exclusions: { services: string[]; processes: string[]; signatures: string[] } = {
      services: [],
      processes: [],
      signatures: []
    };

    try {
      if (fs.existsSync(exclusionsPath)) {
        exclusions = JSON.parse(fs.readFileSync(exclusionsPath, 'utf8'));
      }
    } catch (err) {
      this.logger.warn('Failed to read exclusions file, starting fresh', { error: err });
    }

    // Add target if not already present
    if (!exclusions[category]) {
      exclusions[category] = [];
    }

    if (!exclusions[category].includes(target)) {
      exclusions[category].push(target);

      try {
        fs.writeFileSync(exclusionsPath, JSON.stringify(exclusions, null, 2));
        this.logger.info('Added to exclusion list', { target, category, path: exclusionsPath });
      } catch (err) {
        this.logger.error('Failed to write exclusions file', err);
      }
    } else {
      this.logger.info('Target already in exclusion list', { target, category });
    }
  }

  private isIgnoreInstruction(playbook: PlaybookTask): { isIgnore: boolean; reason: string } {
    const ignorePatterns = [
      /\bignore\b/i,
      /\bsuppress\b/i,
      /\bexclud/i,
      /\bsafe to ignore\b/i,
      /\bignore list\b/i,
      /\bput.+on.+ignore/i,
      /\badd.+to.+ignore/i,
      /\bno action needed\b/i,
      /\bfalse positive\b/i,
      /\bshould be ignored\b/i,
      /\bcan be ignored\b/i,
      /\bnot.+concern\b/i,
      /\bbenign\b/i,
      /\bnormal behavio/i
    ];

    const parts: string[] = [playbook.name || ''];
    if (playbook.steps) {
      for (const step of playbook.steps) {
        parts.push(step.action || '');
        if (step.params) {
          parts.push(JSON.stringify(step.params));
        }
      }
    }
    if ((playbook as any).description) {
      parts.push((playbook as any).description);
    }
    if ((playbook as any).reason) {
      parts.push((playbook as any).reason);
    }

    const textToCheck = parts.join(' ');
    const matched = ignorePatterns.some(p => p.test(textToCheck));

    // Use the playbook's reason/description as the resolution reason
    const reason = (playbook as any).reason ||
                   (playbook as any).description ||
                   playbook.name ||
                   'Server determined this should be ignored';

    return { isIgnore: matched, reason };
  }

  // ============================================
  // SECURITY: Key Rotation Handler
  // ============================================

  private async handleKeyRotationMessage(data: any): Promise<void> {
    this.logger.info('Key rotation request received');

    try {
      const result = await handleKeyRotation(data, this.logger);

      if (result.success) {
        // Send acknowledgment
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
          this.ws.send(JSON.stringify(createRotationAck(result.rotated)));
        }

        // Reload credentials to use new keys
        await this.loadSecureCredentials();
        this.logger.info('Key rotation completed successfully');
      } else {
        // Send error response
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
          this.ws.send(JSON.stringify(createRotationError(result.error || 'Unknown error')));
        }
        this.logger.error('Key rotation failed', { error: result.error });
      }
    } catch (error: any) {
      this.logger.error('Key rotation exception', { error: error.message });
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify(createRotationError(error.message)));
      }
    }
  }

  // ============================================
  // SECURITY: Secure Diagnostic Request Handler
  // ============================================

  private async handleSecureDiagnosticRequest(data: any): Promise<void> {
    // Step 1: Verify HMAC signature if present
    if (data._signature) {
      const verification = await verifyDiagnosticRequest(data);
      if (!verification.valid) {
        this.logger.error('Diagnostic request signature verification failed', {
          error: verification.error,
          session_id: data.session_id
        });
        // Send error response
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
          this.ws.send(JSON.stringify({
            type: 'diagnostic_error',
            session_id: data.session_id,
            error: 'Signature verification failed',
            timestamp: new Date().toISOString()
          }));
        }
        return;
      }
      this.logger.info('Diagnostic request signature verified');
    } else {
      // No signature - REJECT if HMAC is configured (strict enforcement)
      const hmacRequired = await isHmacConfigured();
      if (hmacRequired) {
        this.logger.error('SECURITY: Diagnostic request missing signature - HMAC is configured, rejecting unsigned request');
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
          this.ws.send(JSON.stringify({
            type: 'diagnostic_error',
            session_id: data.session_id,
            error: 'Missing signature - signed requests required',
            timestamp: new Date().toISOString()
          }));
        }
        return;
      }
    }

    // Step 2: Validate diagnostic request structure
    const validation = validateDiagnosticRequest(data);
    if (!validation.valid) {
      this.logger.error('Diagnostic request validation failed', {
        errors: validation.errors,
        session_id: data.session_id
      });
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({
          type: 'diagnostic_error',
          session_id: data.session_id,
          error: 'Validation failed: ' + validation.errors.join(', '),
          timestamp: new Date().toISOString()
        }));
      }
      return;
    }

    // Step 3: Execute the diagnostic
    await this.handleDiagnosticRequest(data);
  }

  // ============================================
  // DIAGNOSTIC REQUEST/RESPONSE (N8N Integration)
  // ============================================

  private async handleDiagnosticRequest(data: any): Promise<void> {
    const { session_id, commands, command, step_id, timeout, scenario, target, reason } = data;

    // Server sends commands as an array — run each one
    if (commands && Array.isArray(commands) && commands.length > 0) {
      this.logger.info('Diagnostic request received (multi-command)', {
        session_id: session_id || 'diag-unknown',
        command_count: commands.length,
        reason
      });

      const results: any[] = [];
      for (const cmd of commands) {
        const cmdStepId = cmd.step_id || `step-${results.length}`;
        const cmdCommand = cmd.command;
        const cmdTimeout = cmd.timeout || 30;

        this.logger.info('Running diagnostic command', {
          step_id: cmdStepId,
          command: cmdCommand ? cmdCommand.substring(0, 100) : undefined
        });

        try {
          const result = await this.executePowerShellCommand(cmdCommand, cmdTimeout);
          const parsedResult = this.parseDiagnosticOutput(result.output, cmdStepId);
          results.push({
            step_id: cmdStepId,
            success: result.exitCode === 0,
            output: result.output,
            error: result.error || null,
            exit_code: result.exitCode,
            parsed_result: parsedResult
          });
          this.logger.info('Diagnostic command completed', { step_id: cmdStepId, success: result.exitCode === 0 });
        } catch (error: any) {
          this.logger.error('Diagnostic command failed', { step_id: cmdStepId, error: error.message });
          results.push({
            step_id: cmdStepId,
            success: false,
            output: null,
            error: error.message,
            exit_code: -1
          });
        }
      }

      // Send all results back in one message
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({
          type: 'diagnostic_result',
          timestamp: new Date().toISOString(),
          device_id: this.deviceInfo.device_id,
          session_id: session_id || 'diag-unknown',
          results,
          command_count: results.length,
          all_success: results.every(r => r.success)
        }));
        this.logger.info('Diagnostic results sent', {
          session_id: session_id || 'diag-unknown',
          total: results.length,
          successful: results.filter(r => r.success).length
        });
      }
      return;
    }

    // Single command fallback
    this.logger.info('Diagnostic request received', {
      session_id,
      step_id,
      command: command ? command.substring(0, 100) : undefined,
      scenario,
      target
    });

    const diagCommand = command || this.buildDiagnosticCommand(scenario, target);
    if (!diagCommand) {
      this.logger.error('Diagnostic request missing command', { data });
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({
          type: 'diagnostic_result',
          timestamp: new Date().toISOString(),
          device_id: this.deviceInfo.device_id,
          session_id,
          step_id,
          success: false,
          error: 'No command or recognized scenario provided',
          exit_code: -1
        }));
      }
      return;
    }

    try {
      const result = await this.executePowerShellCommand(diagCommand, timeout || 30);
      const parsedResult = this.parseDiagnosticOutput(result.output, step_id);

      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({
          type: 'diagnostic_result',
          timestamp: new Date().toISOString(),
          device_id: this.deviceInfo.device_id,
          session_id: session_id,
          step_id: step_id,
          success: result.exitCode === 0,
          output: result.output,
          error: result.error || null,
          exit_code: result.exitCode,
          parsed_result: parsedResult
        }));

        this.logger.info('Diagnostic result sent', { step_id, success: result.exitCode === 0 });
      }
    } catch (error: any) {
      this.logger.error('Diagnostic failed', { step_id, error: error.message });

      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({
          type: 'diagnostic_result',
          timestamp: new Date().toISOString(),
          device_id: this.deviceInfo.device_id,
          session_id: session_id,
          step_id: step_id,
          success: false,
          error: error.message,
          exit_code: -1
        }));
      }
    }
  }

  private async executePowerShellCommand(
    command: string,
    timeoutSeconds: number = 30
  ): Promise<{ exitCode: number; output: string; error: string }> {
    try {
      const { stdout, stderr } = await execAsync(
        `powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "${command.replace(/"/g, '\\"')}"`,
        {
          timeout: timeoutSeconds * 1000,
          maxBuffer: 1024 * 1024
        }
      );

      return {
        exitCode: 0,
        output: stdout.toString(),
        error: stderr.toString()
      };
    } catch (error: any) {
      return {
        exitCode: error.code || -1,
        output: error.stdout?.toString() || '',
        error: error.stderr?.toString() || error.message
      };
    }
  }

  private buildDiagnosticCommand(scenario?: string, target?: string): string | null {
    if (!scenario) return null;
    switch (scenario) {
      case 'service-health':
        return target
          ? `Get-Service -Name '${target}' | Select-Object Name,Status,StartType | ConvertTo-Json`
          : `Get-Service | Where-Object {$_.Status -ne 'Running' -and $_.StartType -eq 'Automatic'} | Select-Object Name,Status,StartType | ConvertTo-Json`;
      case 'disk-health':
        return `Get-PhysicalDisk | Select-Object DeviceId,MediaType,HealthStatus,OperationalStatus,Size | ConvertTo-Json`;
      case 'memory-usage':
        return `Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 10 Name,Id,@{N='MemMB';E={[math]::Round($_.WorkingSet64/1MB)}} | ConvertTo-Json`;
      case 'event-errors':
        return `Get-WinEvent -FilterHashtable @{LogName='System';Level=2;StartTime=(Get-Date).AddHours(-1)} -MaxEvents 20 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,ProviderName,Message | ConvertTo-Json`;
      case 'network':
        return `Test-NetConnection -ComputerName 8.8.8.8 -Port 443 -WarningAction SilentlyContinue | Select-Object ComputerName,TcpTestSucceeded,PingSucceeded,RemotePort | ConvertTo-Json`;
      default:
        this.logger.warn('Unknown diagnostic scenario', { scenario });
        return null;
    }
  }

  private parseDiagnosticOutput(output: string, stepId: string): any {
    if (!stepId) return { raw: output };
    if (stepId.includes('bluetooth') || stepId.includes('device')) {
      return this.parseDeviceOutput(output);
    }
    if (stepId.includes('service')) {
      return this.parseServiceOutput(output);
    }
    if (stepId.includes('event')) {
      return this.parseEventLogOutput(output);
    }
    return { raw_output: output, exit_code: 0 };
  }

  private parseDeviceOutput(output: string): any {
    const lines = output.split('\n').filter(l => l.trim());
    const devices: Array<{ name: string; status: string }> = [];

    for (let i = 3; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;
      const parts = line.split(/\s{2,}/);
      if (parts.length >= 2) {
        devices.push({ name: parts[0], status: parts[parts.length - 1] });
      }
    }

    return {
      device_count: devices.length,
      devices,
      has_errors: devices.some(d => d.status.toLowerCase().includes('error'))
    };
  }

  private parseServiceOutput(output: string): any {
    return {
      service_status: output.toLowerCase().includes('running') ? 'running' : 'stopped',
      raw_output: output
    };
  }

  private parseEventLogOutput(output: string): any {
    const eventCount = (output.match(/\n/g) || []).length;
    return {
      event_count: eventCount,
      has_errors: output.toLowerCase().includes('error'),
      raw_output: output.substring(0, 500)
    };
  }

  private handleDiagnosticComplete(data: any): void {
    const { decision, reason, add_to_ignore_list, issue_signature, playbook } = data;

    this.logger.info('Diagnostic complete', { decision, reason });

    switch (decision) {
      case 'IGNORE':
        if (add_to_ignore_list && issue_signature) {
          this.addToLocalIgnoreList(issue_signature, reason);
          this.logger.info('Added to ignore list via diagnostic', { issue_signature });
        }
        break;

      case 'REMEDIATE':
        if (playbook) {
          this.receivePlaybook(playbook, 'server');
          this.logger.info('Executing remediation playbook from diagnostic');
        }
        break;

      case 'MONITOR_ONLY':
        this.logger.info('Diagnostic result: monitor only', { reason });
        break;

      default:
        this.logger.warn('Unknown diagnostic decision', { decision });
    }
  }

  // ============================================
  // IGNORE LIST MANAGER (data/ignore-list.json)
  // ============================================

  private handleAddToIgnoreList(data: any): void {
    const { signature, reason } = data;

    if (!signature) {
      this.logger.warn('add_to_ignore_list missing signature', { data });
      return;
    }

    this.addToLocalIgnoreList(signature, reason || 'Added by server');
  }

  private addToLocalIgnoreList(signature: string, reason: string): void {
    const ignoreListPath = path.join(process.cwd(), 'data', 'ignore-list.json');

    let ignoreList: { ignored_signatures: Array<{ signature: string; reason: string; added_at: string; verified_by: string }> } = {
      ignored_signatures: []
    };

    // Ensure data directory exists
    const dataDir = path.join(process.cwd(), 'data');
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }

    if (fs.existsSync(ignoreListPath)) {
      try {
        ignoreList = JSON.parse(fs.readFileSync(ignoreListPath, 'utf8'));
      } catch (error) {
        this.logger.warn('Failed to load ignore list, starting fresh', { error });
      }
    }

    // Don't add duplicates
    if (ignoreList.ignored_signatures.some(item => item.signature === signature)) {
      this.logger.info('Signature already in ignore list', { signature });
      return;
    }

    ignoreList.ignored_signatures.push({
      signature,
      reason,
      added_at: new Date().toISOString(),
      verified_by: 'server'
    });

    try {
      fs.writeFileSync(ignoreListPath, JSON.stringify(ignoreList, null, 2));
      this.logger.info('Ignore list updated', { signature, reason });
    } catch (error) {
      this.logger.error('Failed to save ignore list', error);
    }
  }

  private shouldIgnoreSignature(signature: string): boolean {
    const ignoreListPath = path.join(process.cwd(), 'data', 'ignore-list.json');

    if (!fs.existsSync(ignoreListPath)) {
      return false;
    }

    try {
      const ignoreList = JSON.parse(fs.readFileSync(ignoreListPath, 'utf8'));
      return ignoreList.ignored_signatures.some((item: any) => item.signature === signature);
    } catch (error) {
      this.logger.error('Failed to check ignore list', error);
      return false;
    }
  }

  private sendPlaybookResult(playbook: PlaybookTask, status: string, durationMs: number, error?: any): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({
        type: 'playbook_result',
        timestamp: new Date().toISOString(),
        device_id: this.deviceInfo.device_id,
        playbook_id: playbook.id,
        ticket_id: (playbook as any).ticketId || null,
        status,
        execution_time_ms: durationMs,
        steps_executed: playbook.steps?.length || 0,
        error: error ? error.toString() : null,
        source: playbook.source
      }));

      this.logger.info('Playbook result sent to server', {
        playbook_id: playbook.id,
        status
      });
    }
  }

  // Handle Welcome Message from Server (heartbeat already running from on('open'))
  private handleWelcome(data: any): void {
    // Clear welcome timeout — server responded
    if (this.welcomeTimeout) { clearTimeout(this.welcomeTimeout); this.welcomeTimeout = null; }

    this.logger.info('Welcome received from server', {
      client_name: data.client_name,
      tenant_id: data.tenant_id,
      device_id: data.device_id,
      endpoint_id: data.endpoint_id
    });

    // Update device info with server-assigned values
    this.deviceInfo.tenant_id = data.tenant_id || this.deviceInfo.tenant_id;
    this.deviceInfo.device_id = data.device_id || this.deviceInfo.device_id;

    // Store server configuration and update heartbeat interval if provided
    if (data.config) {
      this.serverConfig = data.config;

      // Apply feature flags
      if (this.serverConfig!.features) {
        this.config.autoRemediation = this.serverConfig!.features.autonomous_remediation;
        this.config.autoUpdate = this.serverConfig!.features.auto_update;
      }

      // Update system monitor thresholds from server config
      if (this.serverConfig!.thresholds) {
        this.systemMonitor.updateThresholds(this.serverConfig!.thresholds);
      }

      // Update heartbeat interval if server specifies a different one
      const heartbeatMs = this.serverConfig!.monitoring?.heartbeat_interval || 30000;
      if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = setInterval(() => this.sendHeartbeat(), heartbeatMs);

      this.logger.info('Server config applied', {
        heartbeat_interval: heartbeatMs,
        thresholds: this.serverConfig!.thresholds,
        features: this.serverConfig!.features
      });
    }
    // No else needed — heartbeat already running from on('open')

    // Apply severity escalation and flap detection config from server
    const sc = this.serverConfig as any;
    if (sc?.severity_escalation) {
      this.stateTracker.updateSeverityConfig(sc.severity_escalation);
    }
    if (sc?.flap_detection) {
      this.stateTracker.updateFlapConfig(sc.flap_detection);
    }
  }

  // ============================================
  // EVENT MONITORING (UPDATED WITH SIGNATURES)
  // ============================================

  /**
   * UPDATED: Called when EventMonitor detects an issue with a matching runbook
   * NOW USES SIGNATURE SYSTEM AND TIERED DECISION LOGIC
   */
  private handleIssueDetected(event: EventLogEntry, runbook?: RunbookMatch): void {
    this.logger.info('Issue detected', {
      eventId: event.id,
      source: event.source,
      hasRunbook: !!runbook
    });

    // Gate 1: Maintenance window check
    const maintenanceCheck = this.maintenanceManager.isUnderMaintenance(
      'event-log',
      event.raw?.serviceName,
      `event:${event.source}:${event.id}`
    );
    if (maintenanceCheck.suppressed) {
      this.logger.info('Event suppressed by maintenance window', {
        eventId: event.id,
        source: event.source,
        window: maintenanceCheck.window?.name
      });
      return;
    }

    // Gate 2: State tracking deduplication
    const resourceId = `event:${event.source}:${event.id}`;
    const stateChange = this.stateTracker.checkState(resourceId, 'service', event.level, undefined, { eventId: event.id, source: event.source });
    if (!stateChange) {
      this.logger.debug('Event state unchanged, suppressing', { resourceId });
      return;
    }

    // Generate signature from event
    const signature = this.signatureGenerator.generateFromEvent(event, this.deviceInfo);
    
    this.logger.info('Signature generated', {
      signature_id: signature.signature_id,
      confidence: signature.confidence_local,
      severity: signature.severity,
      symptoms: signature.symptoms.length
    });

    // FAST PATH: Check remediation memory for cached successful solution
    const cachedPlaybookId = this.remediationMemory.findCachedSolution(
      signature.signature_id.split('-').slice(0, 2).join('-'), // normalize signal key
      os.hostname()
    );
    // Also check by event source+id as signal key
    const eventSignalKey = `${event.source}-${event.id}`;
    const cachedByEvent = cachedPlaybookId || this.remediationMemory.findCachedSolution(eventSignalKey, os.hostname());

    if (cachedByEvent && runbook) {
      this.logger.info('Cache hit: replaying known successful remediation', {
        signalKey: eventSignalKey,
        cachedPlaybook: cachedByEvent,
        runbook: runbook.runbookId
      });
      this.executeLocalRemediation(signature, runbook);
      return;
    }

    // Determine action based on signature, confidence, and runbook class
    if (runbook) {
      const riskClass = this.runbookClassifier.getRunbookClass(runbook.runbookId);
      const canAutoExecute = this.runbookClassifier.canAutoExecute(
        runbook.runbookId,
        signature.confidence_local
      );

      this.logger.info('Runbook classification', {
        runbook_id: runbook.runbookId,
        risk_class: riskClass,
        can_auto_execute: canAutoExecute,
        confidence: signature.confidence_local
      });

      if (canAutoExecute && riskClass === 'A' && signature.confidence_local >= 85) {
        // Class A with high confidence - Auto execute locally
        this.executeLocalRemediation(signature, runbook);
      } else {
        // Class B/C or low confidence - Escalate to server
        this.escalateToServer(signature, runbook);
      }
    } else {
      // No runbook - Escalate for diagnosis
      this.escalateToServer(signature, null);
    }
  }

  /**
   * UPDATED: Handle system issues with signature system
   */
  private handleSystemIssue(signal: SystemSignal): void {
    this.logger.warn('System signal detected', {
      id: signal.id,
      category: signal.category,
      severity: signal.severity,
      metric: signal.metric,
      value: signal.value
    });

    // Gate 1: Maintenance window check
    const maintenanceCheck = this.maintenanceManager.isUnderMaintenance(
      signal.category,
      signal.metadata?.serviceName,
      signal.id
    );
    if (maintenanceCheck.suppressed) {
      this.logger.info('Signal suppressed by maintenance window', {
        signal: signal.id,
        window: maintenanceCheck.window?.name,
        reason: maintenanceCheck.reason
      });
      this.sendTelemetry(signal);
      return;
    }

    // Gate 2: State tracking deduplication
    const resourceId = this.deriveResourceId(signal);
    const currentState = this.deriveCurrentState(signal);
    const resourceType = this.deriveResourceType(signal);
    const stateChange = this.stateTracker.checkState(resourceId, resourceType, currentState, signal.severity as any, signal.metadata);

    if (!stateChange) {
      this.sendTelemetry(signal);
      this.patternDetector.recordOccurrence(
        signal.id, signal.category, os.hostname(),
        signal.severity as 'critical' | 'warning' | 'info', signal.metadata
      );
      return;
    }

    // Gate 3: Dependency awareness — suppress downstream service alerts
    if (signal.category === 'services' && signal.metadata?.serviceName) {
      const depCheck = this.stateTracker.isDownstreamOfDownParent(signal.metadata.serviceName);
      if (depCheck.isDownstream) {
        this.logger.info('Suppressing downstream service alert', {
          service: signal.metadata.serviceName,
          downParents: depCheck.downParents
        });
        this.sendTelemetry(signal);
        return;
      }
    }

    // Gate 4: Flap detection — replace signal with FLAP signal
    if (stateChange.isFlap) {
      signal = {
        ...signal,
        id: `FLAP_${resourceId}`,
        severity: 'warning',
        metric: 'flap_detected',
        value: stateChange.transitionCount,
        message: `Resource ${resourceId} is flapping: ${stateChange.transitionCount} state changes in ${this.stateTracker.getFlapConfig().windowMinutes} minutes`,
        metadata: {
          ...signal.metadata,
          flapTransitionCount: stateChange.transitionCount,
          originalSignalId: signal.id
        }
      } as SystemSignal;
    }

    // Stream telemetry to server in real-time
    this.sendTelemetry(signal);

    // Record pattern
    this.patternDetector.recordOccurrence(
      signal.id,
      signal.category,
      os.hostname(),
      signal.severity as 'critical' | 'warning' | 'info',
      signal.metadata
    );

    // Update hardware health score if signal has a component type
    if (signal.componentType) {
      const componentKey = signal.componentType === 'disk'
        ? `disk:${signal.metadata?.DeviceId || signal.metadata?.drive || '0'}`
        : signal.componentType;
      this.patternDetector.updateHealthScore(signal.id, componentKey, signal.severity);
    }

    // NEW: Generate signature from system signal
    const signature = this.signatureGenerator.generateFromSystemSignal(signal, this.deviceInfo);
    
    this.logger.info('System signature generated', {
      signature_id: signature.signature_id,
      confidence: signature.confidence_local,
      severity: signature.severity
    });

    // Create playbook for system signal if possible
    const playbook = this.createPlaybookForSystemSignal(signal);
    
    if (playbook && signature.confidence_local >= 85) {
      // High confidence - execute locally
      const ticketId = this.actionTicketManager.createActionTicket(
        signature.signature_id,
        playbook.id,
        `System remediation: ${playbook.name}`,
        playbook.steps.length
      );
      
      this.activeTickets.set(playbook.id, ticketId);
      this.actionTicketManager.markInProgress(ticketId, playbook.id);
      this.receivePlaybook(playbook, 'local');
      
    } else if (playbook) {
      // Low confidence - escalate
      this.escalateSystemIssueToServer(signature, playbook);
    } else {
      // No local playbook - escalate to server for decision
      // Server has ignore list and can send appropriate runbook
      this.logger.info('No local playbook - escalating to server', {
        signature_id: signature.signature_id,
        category: signal.category,
        metric: signal.metric
      });
      this.escalateToServer(signature, null);
    }
  }

  // NEW METHOD: Execute Local Remediation (Class A)
  private executeLocalRemediation(signature: DeviceSignature, runbook: RunbookMatch): void {
    this.logger.info('Executing local Class A remediation', {
      signature_id: signature.signature_id,
      runbook_id: runbook.runbookId,
      confidence: signature.confidence_local
    });

    // Create action ticket with signature_id stored
    const ticketId = this.actionTicketManager.createActionTicket(
      signature.signature_id,
      runbook.runbookId,
      `Auto-remediation: ${runbook.name}`,
      runbook.steps.length
    );

    // Store signature in pending escalations for potential failure escalation
    this.pendingEscalations.set(signature.signature_id, signature);

    this.actionTicketManager.markInProgress(ticketId, runbook.runbookId);

    // Convert runbook to playbook
    const playbook: PlaybookTask = {
      id: `playbook-${Date.now()}`,
      name: runbook.name,
      priority: 'high',
      source: 'local',
      steps: runbook.steps,
      createdAt: new Date()
    };

    // Link and execute
    this.activeTickets.set(playbook.id, ticketId);
    this.receivePlaybook(playbook, 'local');

    // Record action
    this.recentActions.unshift({
      playbook_id: runbook.runbookId,
      result: 'success', // Will be updated later
      timestamp: new Date().toISOString()
    });

    if (this.recentActions.length > 5) {
      this.recentActions = this.recentActions.slice(0, 5);
    }
    
    this.broadcastTicketUpdate();
  }

  // NEW METHOD: Escalate to Server (Tier 2) - With Pre-Escalation Troubleshooting
  private async escalateToServer(signature: DeviceSignature, runbook: RunbookMatch | null): Promise<void> {
    // Check ignore list before escalating
    if (this.shouldIgnoreSignature(signature.signature_id)) {
      this.logger.debug('Ignoring signal - on ignore list', {
        signal_id: signature.signature_id
      });
      return;
    }

    // Check if signal is awaiting technician review - don't re-escalate
    if (this.isAwaitingReview(signature.signature_id)) {
      this.logger.debug('Signal is awaiting technician review - not re-escalating', {
        signal_id: signature.signature_id
      });
      return;
    }

    // Deduplication: skip if same signature was escalated within cooldown window
    const now = Date.now();
    const lastEscalated = this.escalationCooldowns.get(signature.signature_id);
    if (lastEscalated && (now - lastEscalated) < this.ESCALATION_COOLDOWN_MS) {
      this.logger.debug('Skipping duplicate escalation (cooldown active)', {
        signature_id: signature.signature_id,
        cooldown_remaining_ms: this.ESCALATION_COOLDOWN_MS - (now - lastEscalated)
      });
      return;
    }

    this.logger.info('Escalating to server (Tier 2)', {
      signature_id: signature.signature_id,
      has_runbook: !!runbook,
      confidence: signature.confidence_local
    });

    // Store pending escalation and matched runbook
    this.pendingEscalations.set(signature.signature_id, signature);
    if (runbook) {
      this.pendingRunbooks.set(signature.signature_id, runbook);
    }

    // Mark as escalated for dedup cooldown
    this.escalationCooldowns.set(signature.signature_id, now);

    // Run pre-escalation troubleshooting to collect diagnostic data
    let diagnosticData: DiagnosticData | null = null;
    try {
      diagnosticData = await this.troubleshootingRunner.runTroubleshooting(signature, 15000);
      if (diagnosticData) {
        this.logger.info('Pre-escalation diagnostics collected', {
          signature_id: signature.signature_id,
          category: diagnosticData.category,
          steps_collected: Object.keys(diagnosticData.data).length,
          duration_ms: diagnosticData.duration_ms
        });
      }
    } catch (error: any) {
      // Log but don't block escalation if troubleshooting fails
      this.logger.warn('Pre-escalation troubleshooting failed', {
        signature_id: signature.signature_id,
        error: error.message
      });
    }

    // If not connected, fall back to manual ticket immediately
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      this.logger.warn('WebSocket not connected, creating manual ticket', {
        signature_id: signature.signature_id
      });
      this.createManualTicket(signature);
      return;
    }

    // Check if critical severity — flush immediately
    const isCritical = signature.severity === 'critical' || signature.severity === 'high';
    if (isCritical) {
      this.sendEscalationNow(signature, runbook, diagnosticData);
      return;
    }

    // Batch: queue for batched send
    this.escalationBatch.push({ signature, runbook, diagnosticData });
    if (!this.batchTimer) {
      this.batchTimer = setTimeout(() => this.flushEscalationBatch(), this.BATCH_FLUSH_MS);
    }
  }

  private sendEscalationNow(signature: DeviceSignature, runbook: RunbookMatch | null, diagnosticData?: DiagnosticData | null): void {
    const escalationPayload = this.escalationProtocol.buildEscalationPayload(
      signature,
      runbook,
      this.recentActions,
      diagnosticData
    );

    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({
        type: 'escalation',
        ...escalationPayload
      }));
      this.logger.info('Escalation sent to server', {
        signature_id: escalationPayload.signature_id,
        requested_outcome: escalationPayload.requested_outcome,
        has_diagnostic_data: !!escalationPayload.pre_escalation_diagnostics,
        diagnostic_category: escalationPayload.pre_escalation_diagnostics?.category
      });
    }
  }

  private flushEscalationBatch(): void {
    this.batchTimer = null;
    if (this.escalationBatch.length === 0) return;

    const batch = this.escalationBatch.splice(0);

    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      this.logger.warn('WebSocket not connected, creating manual tickets for batch', {
        batch_size: batch.length
      });
      for (const item of batch) {
        this.createManualTicket(item.signature);
      }
      return;
    }

    // Single item — send as regular escalation
    if (batch.length === 1) {
      this.sendEscalationNow(batch[0].signature, batch[0].runbook, batch[0].diagnosticData);
      return;
    }

    // Multiple items — send as batch (include diagnostic data)
    const escalations = batch.map(item =>
      this.escalationProtocol.buildEscalationPayload(item.signature, item.runbook, this.recentActions, item.diagnosticData)
    );

    this.ws.send(JSON.stringify({
      type: 'batch_escalation',
      escalations,
      batch_size: escalations.length
    }));

    this.logger.info('Batch escalation sent to server', {
      batch_size: escalations.length,
      signature_ids: escalations.map(e => e.signature_id),
      with_diagnostics: escalations.filter(e => e.pre_escalation_diagnostics).length
    });
  }

  // NEW METHOD: Escalate System Issue to Server
  private escalateSystemIssueToServer(signature: DeviceSignature, playbook: PlaybookTask): void {
    this.logger.info('Escalating system issue to server', {
      signature_id: signature.signature_id,
      playbook_id: playbook.id
    });

    // Create runbook match from playbook
    const runbookMatch: RunbookMatch = {
      runbookId: playbook.id,
      name: playbook.name,
      confidence: signature.confidence_local / 100,
      trigger: 'system-monitor',
      steps: playbook.steps as any[] // Type assertion to fix PlaybookStep vs RunbookStep mismatch
    };

    this.escalateToServer(signature, runbookMatch);
  }

  // NEW METHOD: Create Manual Ticket
  private createManualTicket(signature: DeviceSignature): void {
    const ticketId = `ticket-manual-${Date.now()}`;
    
    const description = `Manual review required: ${signature.symptoms.map(s => 
      `${s.type}:${s.severity}`
    ).join(', ')} affecting ${signature.targets.map(t => t.name).join(', ')}`;
    
    const ticket: Ticket = {
      ticket_id: ticketId,
      timestamp: new Date().toISOString(),
      type: 'manual-review',
      description: description,
      status: 'open',
      source: 'monitoring',
      computer_name: os.hostname(),
      escalated: 1
    };

    this.ticketDb.createTicket(ticket);
    this.ticketDb.markAsEscalated(ticketId);
    
    this.logger.info('Manual ticket created', { 
      ticketId, 
      signature_id: signature.signature_id 
    });
    
    this.broadcastTicketUpdate();
  }

  // NEW METHOD: Escalate Failed Remediation
  private escalateFailedRemediation(ticketId: string, playbookId: string, error: any): void {
    this.logger.info('Escalating failed remediation to server', {
      ticketId,
      playbookId,
      error: error?.toString()
    });

    // Try to get the original signature from the ticket
    const ticket = this.ticketDb.getTicket(ticketId);
    if (!ticket) {
      this.logger.error('Cannot escalate - ticket not found', { ticketId });
      return;
    }

    // Extract signature_id from ticket if stored, or find in pending escalations
    let signature: DeviceSignature | undefined;
    
    // Look through pending escalations
    for (const [sigId, sig] of this.pendingEscalations.entries()) {
      if (ticket.description && ticket.description.includes(sigId)) {
        signature = sig;
        break;
      }
    }

    if (!signature) {
      // Reconstruct minimal signature from ticket
      signature = {
        signature_id: `signature-failed-${Date.now()}`,
        tenant_id: this.deviceInfo.tenant_id,
        device_id: this.deviceInfo.device_id,
        timestamp: new Date().toISOString(),
        severity: 'high', // Escalate because remediation failed
        confidence_local: 50, // Lower confidence since fix failed
        symptoms: [{
          type: 'remediation_failure',
          severity: 'high',
          description: `Failed to execute playbook: ${playbookId}`,
          details: {
            playbook_id: playbookId,
            error: error?.toString(),
            original_issue: ticket.description
          }
        }],
        targets: [{
          type: 'playbook',
          name: playbookId
        }],
        context: {
          os_build: 'Windows',
          os_version: os.release(),
          device_role: this.deviceInfo.role || 'workstation'
        }
      } as any;
    } else {
      // Enhance existing signature with failure info
      signature.symptoms.push({
        type: 'remediation_failure',
        severity: 'high',
        description: `Remediation failed: ${error?.toString()}`,
        details: {
          playbook_id: playbookId,
          error: error?.toString()
        }
      } as any);
      signature.confidence_local = Math.min(signature.confidence_local, 60); // Lower confidence
      signature.severity = 'high'; // Escalate severity
    }

    // Update recent actions to include this failure
    this.recentActions.unshift({
      playbook_id: playbookId,
      result: 'failure',
      timestamp: new Date().toISOString()
    });

    if (this.recentActions.length > 5) {
      this.recentActions = this.recentActions.slice(0, 5);
    }

    // Escalate to server with failure context (signature is guaranteed non-undefined here)
    if (signature) {
      this.escalateToServer(signature, null);
    }
  }

  // FIXED: Legacy escalation path now uses signature system
  private handleEscalationNeeded(event: EventLogEntry, reason: string): void {
    this.logger.warn('Escalation needed (legacy path)', {
      eventId: event.id,
      reason
    });

    // NEW: Generate signature from event (convert legacy escalation to new system)
    const signature = this.signatureGenerator.generateFromEvent(event, this.deviceInfo);
    
    this.logger.info('Legacy escalation converted to signature', {
      signature_id: signature.signature_id,
      reason
    });

    // Create escalated ticket
    const ticketId = `ticket-escalated-${Date.now()}`;
    const ticket: Ticket = {
      ticket_id: ticketId,
      timestamp: new Date(event.timeCreated).toISOString(),
      type: this.getTicketType(event),
      description: `[ESCALATED] ${reason}: ${event.source} - ${event.message.substring(0, 150)}`,
      status: 'open',
      source: 'event-log',
      computer_name: os.hostname(),
      event_id: event.id,
      event_source: event.source,
      escalated: 1
    };

    try {
      this.ticketDb.createTicket(ticket);
      this.ticketDb.markAsEscalated(ticketId);
      this.logger.info('Escalated ticket created', { ticketId, reason });
      this.broadcastTicketUpdate();
    } catch (error) {
      this.logger.error('Failed to create escalated ticket', error);
    }

    // FIXED: Use new escalation protocol instead of legacy format
    this.escalateToServer(signature, null);
  }

  private getTicketType(event: EventLogEntry): string {
    const eventTypeMap: Record<number, string> = {
      7034: 'service-crash',
      7031: 'service-crash',
      7036: 'service-change',
      1000: 'application-crash',
      1001: 'application-hang',
      7: 'disk-error',
      11: 'disk-error',
      15: 'disk-error',
      2013: 'disk-timeout',
      1014: 'dns-failure',
      1015: 'dns-failure'
    };

    return eventTypeMap[event.id] || 'system-event';
  }

  private determinePriority(confidence: number): 'critical' | 'high' | 'medium' | 'low' {
    if (confidence >= 0.9) return 'high';
    if (confidence >= 0.7) return 'medium';
    return 'low';
  }

  // ============================================
  // PLAYBOOK SYSTEM (Unchanged)
  // ============================================

  public async receivePlaybook(playbook: PlaybookTask, source: 'server' | 'admin' | 'local'): Promise<void> {
    playbook.source = source;
    playbook.createdAt = new Date();

    this.log(`Received playbook: ${playbook.name} (${source} - ${playbook.priority})`);

    // SECURITY: Verify and validate server playbooks
    if (source === 'server') {
      // Step 1: Verify HMAC signature if present
      const pbAny = playbook as any;
      if (pbAny._signature) {
        const verification = await verifyPlaybook(playbook);
        if (!verification.valid) {
          this.logger.error('Playbook signature verification failed', {
            error: verification.error,
            playbookId: playbook.id
          });
          return; // Reject the playbook
        }
        this.logger.info('Playbook signature verified', { playbookId: playbook.id });
      } else {
        // No signature - REJECT if HMAC is configured (strict enforcement)
        const hmacRequired = await isHmacConfigured();
        if (hmacRequired) {
          this.logger.error('SECURITY: Server playbook missing signature - HMAC is configured, rejecting unsigned playbook', {
            playbookId: playbook.id
          });
          return; // Reject the playbook
        }
      }

      // Step 2: Validate playbook structure and step types
      const validation = validatePlaybook(playbook);
      if (!validation.valid) {
        this.logger.error('Playbook validation failed', {
          errors: validation.errors,
          playbookId: playbook.id
        });
        return; // Reject the playbook
      }
      this.logger.info('Playbook validated successfully', { playbookId: playbook.id });
    }

    // Check if this is an ignore instruction from the server
    if (source === 'server') {
      const ignoreCheck = this.isIgnoreInstruction(playbook);
      if (ignoreCheck.isIgnore) {
        this.logger.info('Playbook detected as ignore instruction', {
          playbookId: playbook.id,
          reason: ignoreCheck.reason
        });

        const signalId = (playbook as any).signalId || playbook.id;

        // Add to local ignore list so this signal is never sent to server again
        this.addToLocalIgnoreList(signalId, ignoreCheck.reason);

        // Also add to exclusion list for local processing
        const inferred = this.inferExclusionFromSignature(signalId);
        this.addToExclusionList(inferred.target, inferred.category);

        // Close associated tickets
        const tickets = this.ticketDb.getTickets();
        for (const ticket of tickets) {
          if (ticket.status !== 'resolved' &&
              ticket.description && ticket.description.includes(signalId)) {
            this.ticketDb.closeTicket(ticket.ticket_id, ignoreCheck.reason, 'success');
            this.logger.info('Ticket resolved via ignore playbook', {
              ticketId: ticket.ticket_id,
              reason: ignoreCheck.reason
            });
          }
        }

        // Remove from pending escalations
        this.pendingEscalations.delete(signalId);
        this.broadcastTicketUpdate();
        this.reportPlaybookResult(playbook.id, 'success');
        return;
      }
    }

    const signalId = (playbook as any).signalId || playbook.id;
    const deviceId = os.hostname();

    const memoryCheck = this.remediationMemory.shouldAttemptRemediation(
      signalId,
      deviceId,
      playbook.id
    );
    
    if (!memoryCheck.allowed) {
      this.logger.warn('Remediation blocked by memory system', {
        playbookId: playbook.id,
        reason: memoryCheck.reason
      });
      
      this.reportPlaybookResult(playbook.id, 'skipped', memoryCheck.reason);
      return;
    }

    if (this.playbookQueue.length >= 50) {
      this.logger.warn('Playbook queue full, rejecting playbook', { playbookId: playbook.id });
      this.reportPlaybookResult(playbook.id, 'skipped', 'Queue full (limit: 50)');
      return;
    }

    this.playbookQueue.push(playbook);

    this.playbookQueue.sort((a, b) => {
      const sourceOrder = { server: 0, admin: 1, local: 2 };
      const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      
      if (sourceOrder[a.source] !== sourceOrder[b.source]) {
        return sourceOrder[a.source] - sourceOrder[b.source];
      }
      
      return priorityOrder[a.priority] - priorityOrder[b.priority];
    });

    if (!this.isExecutingPlaybook) {
      this.processPlaybookQueue();
    }
  }

  private async processPlaybookQueue(): Promise<void> {
    if (this.isExecutingPlaybook || this.playbookQueue.length === 0) {
      return;
    }

    this.isExecutingPlaybook = true;

    while (this.playbookQueue.length > 0) {
      const playbook = this.playbookQueue.shift()!;
      
      this.log(`Executing playbook: ${playbook.name}`);
      
      const startTime = Date.now();
      const signalId = (playbook as any).signalId || playbook.id;
      const deviceId = os.hostname();
      
      try {
        await this.executePlaybook(playbook);
        const duration = Date.now() - startTime;

        this.log(`Playbook completed: ${playbook.name}`);
        this.reportPlaybookResult(playbook.id, 'success');
        this.sendPlaybookResult(playbook, 'success', duration);

        this.remediationMemory.recordAttempt(
          playbook.id,
          signalId,
          deviceId,
          'success',
          duration
        );

        // Save successful server runbooks for future local use
        if (playbook.source === 'server') {
          this.saveServerRunbook(playbook);
        }
      } catch (error) {
        const duration = Date.now() - startTime;

        this.log(`Playbook failed: ${playbook.name}`, error);
        this.reportPlaybookResult(playbook.id, 'failed', error);
        this.sendPlaybookResult(playbook, 'failed', duration, error);

        this.remediationMemory.recordAttempt(
          playbook.id,
          signalId,
          deviceId,
          'failure',
          duration,
          error?.toString()
        );
      }
    }

    this.isExecutingPlaybook = false;
  }

  private async executePlaybook(playbook: PlaybookTask): Promise<void> {
    for (let i = 0; i < playbook.steps.length; i++) {
      const step = playbook.steps[i];
      this.log(`  Executing step: ${step.type} - ${step.action}`);

      if (step.requiresApproval && !this.config.autoRemediation) {
        this.log('  Step requires approval, skipping (auto-remediation disabled)');
        continue;
      }

      const isVerification = step.allowFailure || this.isVerificationStep(step, playbook.steps, i);

      try {
        await this.executeStep(step);
      } catch (error) {
        if (isVerification) {
          this.log(`  Verification step result (non-fatal): ${step.action}`, error);
          continue;
        }
        this.log(`  Step failed: ${step.action}`, error);
        throw error;
      }
    }
  }

  private isVerificationStep(step: PlaybookStep, allSteps: PlaybookStep[], index: number): boolean {
    return isVerificationStep(step, allSteps, index);
  }

  private async executeStep(step: PlaybookStep): Promise<void> {
    const timeout = step.timeout || 60000;

    switch (step.type) {
      case 'powershell':
        await this.executePowerShell(step.action, step.params, timeout);
        break;
      case 'service':
        await this.executeServiceAction(step.action, step.params);
        break;
      case 'registry':
        await this.executeRegistryAction(step.action, step.params);
        break;
      case 'file':
        await this.executeFileAction(step.action, step.params);
        break;
      case 'wmi':
        await this.executeWMIQuery(step.action, step.params);
        break;
      case 'diagnostic':
        await this.runDiagnostic(step.action);
        break;
      case 'reboot':
        await this.executeReboot(step.params);
        break;
      case 'user-prompt':
        await this.executeUserPrompt(step.action, step.params);
        break;
      default:
        throw new Error(`Unknown step type: ${step.type}`);
    }
  }

  private translatePlainEnglishToPowerShell(script: string): string | null {
    // Translate common plain-English patterns from server into real PowerShell
    let match: RegExpMatchArray | null;

    // "Start service <name>"
    match = script.match(/^Start service (.+)$/i);
    if (match) return `Start-Service -Name '${match[1]}' -ErrorAction Stop`;

    // "Stop service <name>"
    match = script.match(/^Stop service (.+)$/i);
    if (match) return `Stop-Service -Name '${match[1]}' -Force -ErrorAction Stop`;

    // "Restart service <name>"
    match = script.match(/^Restart service (.+)$/i);
    if (match) return `Restart-Service -Name '${match[1]}' -Force -ErrorAction Stop`;

    // "Set service <name> to start automatically"
    match = script.match(/^Set service (.+) to start automatically$/i);
    if (match) return `Set-Service -Name '${match[1]}' -StartupType Automatic -ErrorAction Stop`;

    // "Kill and restart <name> process"
    match = script.match(/^Kill and restart (.+) process$/i);
    if (match) return `Stop-Process -Name '${match[1]}' -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 2; Start-Process '${match[1]}' -ErrorAction SilentlyContinue`;

    // "Kill <name> process"
    match = script.match(/^Kill (.+) process$/i);
    if (match) return `Stop-Process -Name '${match[1]}' -Force -ErrorAction Stop`;

    // "Restart <name> process"
    match = script.match(/^Restart (.+) process$/i);
    if (match) return `Stop-Process -Name '${match[1]}' -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 2; Start-Process '${match[1]}' -ErrorAction SilentlyContinue`;

    // "Restart computer" / "Reboot computer" / "Reboot machine"
    match = script.match(/^(Restart|Reboot)\s+(computer|machine|system)$/i);
    if (match) return `shutdown /r /t 30 /c "OPSIS Agent: Restarting to complete remediation"`;

    // "Shutdown computer"
    match = script.match(/^Shut\s*down\s+(computer|machine|system)$/i);
    if (match) return `shutdown /s /t 30 /c "OPSIS Agent: Shutting down"`;

    return null;
  }

  private isValidPowerShell(script: string): boolean {
    // Check if the script looks like a real PowerShell command (contains a cmdlet or known executable)
    const cmdletPattern = /^[\w\-]+(-[\w]+)?\s/; // e.g. Get-Service, Stop-Process
    const execPattern = /\.(exe|ps1|cmd|bat)\b/i;
    const pipelinePattern = /\|/;
    const variablePattern = /\$/;
    const knownCmdlets = ['Clear-', 'Get-', 'Set-', 'Start-', 'Stop-', 'Restart-', 'Remove-', 'New-', 'Invoke-', 'Test-', 'Write-', 'Out-', 'Import-', 'Export-', 'Add-', 'Enable-', 'Disable-', 'Register-', 'Unregister-'];

    return cmdletPattern.test(script) ||
           execPattern.test(script) ||
           pipelinePattern.test(script) ||
           variablePattern.test(script) ||
           knownCmdlets.some(c => script.startsWith(c));
  }

  private async executePowerShell(script: string, params: Record<string, any>, timeout: number): Promise<string> {
    // Translate plain-English commands from server into real PowerShell
    let effectiveScript = script;
    if (!this.isValidPowerShell(script)) {
      const translated = this.translatePlainEnglishToPowerShell(script);
      if (translated) {
        this.logger.info('Translated plain-English to PowerShell', { original: script, translated });
        effectiveScript = translated;
      } else {
        this.logger.error('Rejecting invalid PowerShell command', { script });
        throw new Error(`Invalid PowerShell command (not a valid cmdlet or known pattern): ${script}`);
      }
    }

    let command = `powershell -NoProfile -ExecutionPolicy Bypass -Command "${effectiveScript}"`;

    if (params && Object.keys(params).length > 0) {
      const paramString = Object.entries(params)
        .map(([key, value]) => {
          const sanitized = String(value).replace(/'/g, "''");
          return `-${key} '${sanitized}'`;
        })
        .join(' ');
      command += ` ${paramString}`;
    }

    const { stdout, stderr } = await execAsync(command, { timeout });
    
    if (stderr) {
      this.log(`PowerShell stderr: ${stderr}`);
    }

    return stdout;
  }

  // FIXED: Use PowerShell for service actions (handles both service names and display names)
  private async executeServiceAction(action: string, params: Record<string, any>): Promise<void> {
    const { serviceName } = params;

    // Validate service name against safe pattern
    if (!/^[\w\s\-\.]+$/.test(serviceName)) {
      throw new Error(`Invalid service name: ${serviceName}`);
    }

    // Block actions on protected services
    if (isProtectedService(serviceName) && (action === 'stop' || action === 'restart')) {
      this.logger.error('Blocked action on protected service', { serviceName, action });
      throw new Error(`Cannot ${action} protected service: ${serviceName}`);
    }

    if (action === 'restart') {
      // Use PowerShell Restart-Service which accepts both names and display names
      await execAsync(`powershell -Command "Restart-Service -Name '${serviceName}' -Force -ErrorAction Stop"`);
    } else if (action === 'start') {
      await execAsync(`powershell -Command "Start-Service -Name '${serviceName}' -ErrorAction Stop"`);
    } else if (action === 'stop') {
      await execAsync(`powershell -Command "Stop-Service -Name '${serviceName}' -Force -ErrorAction Stop"`);
    }
  }

  private async executeRegistryAction(action: string, params: Record<string, any>): Promise<void> {
    const { key, valueName, valueData, valueType } = params;

    // Validate registry key path format
    if (!/^(HKLM|HKCU|HKCR|HKU|HKCC)\\[\w\\.\- ]+$/.test(key)) {
      throw new Error(`Invalid registry key path: ${key}`);
    }

    // Escape double quotes in values
    const safeValueName = String(valueName).replace(/"/g, '\\"');
    const safeValueData = valueData != null ? String(valueData).replace(/"/g, '\\"') : '';

    if (action === 'set') {
      await execAsync(`reg add "${key}" /v "${safeValueName}" /t ${valueType} /d "${safeValueData}" /f`);
    } else if (action === 'delete') {
      await execAsync(`reg delete "${key}" /v "${safeValueName}" /f`);
    }
  }

  private async executeFileAction(action: string, params: Record<string, any>): Promise<void> {
    const { path: filePath, content, destination } = params;

    if (action === 'create') {
      fs.writeFileSync(filePath, content);
    } else if (action === 'delete') {
      fs.unlinkSync(filePath);
    } else if (action === 'copy') {
      fs.copyFileSync(filePath, destination);
    }
  }

  private async executeWMIQuery(query: string, params: Record<string, any>): Promise<void> {
    const psScript = `Get-WmiObject -Query "${query}"`;
    await this.executePowerShell(psScript, params, 30000);
  }

  // UPDATED: Report playbook result with escalation on failure
  private reportPlaybookResult(playbookId: string, status: string, error?: any): void {
    const ticketId = this.activeTickets.get(playbookId);
    if (ticketId) {
      try {
        if (status === 'success') {
          this.ticketDb.closeTicket(
            ticketId,
            `Auto-resolved by playbook: ${playbookId}`,
            'success'
          );
          this.logger.info('Ticket auto-resolved', { ticketId, playbookId });
        } else {
          // ADDED: Escalate failed Class A remediations to server
          this.logger.warn('Class A remediation failed - escalating to server', { 
            ticketId, 
            playbookId,
            error: error?.toString()
          });
          
          // Escalate the failed remediation
          this.escalateFailedRemediation(ticketId, playbookId, error);
          
          // Still mark ticket as failed locally
          this.ticketDb.updateTicketStatus(ticketId, 'failed');
          this.ticketDb.closeTicket(
            ticketId,
            `Playbook failed: ${error?.toString() || 'Unknown error'}`,
            'failure'
          );
          this.logger.error('Ticket marked as failed', { ticketId, playbookId, error });
        }

        this.activeTickets.delete(playbookId);
        this.broadcastTicketUpdate();
      } catch (err) {
        this.logger.error('Failed to update ticket after playbook', err);
      }
    }

    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({
        type: 'action_result',
        timestamp: new Date().toISOString(),
        data: {
          playbook_id: playbookId,
          ticket_id: ticketId,
          status: status,
          error: error ? error.toString() : undefined
        }
      }));
    }
  }

  // ============================================
  // AUTO-UPDATE & DIAGNOSTICS (Unchanged)
  // ============================================

  private startUpdateChecker(): void {
    const checkInterval = this.config.updateCheckInterval * 60 * 1000;
    
    this.updateCheckTimer = setInterval(() => {
      this.checkForUpdates();
    }, checkInterval);

    setTimeout(() => this.checkForUpdates(), 10000);
  }
  
  private startPatternAnalysis(): void {
    const analysisInterval = 60 * 60 * 1000;
    
    this.patternAnalysisTimer = setInterval(() => {
      this.analyzeAndReportPatterns();
    }, analysisInterval);
    
    setTimeout(() => this.analyzeAndReportPatterns(), 5 * 60 * 1000);
  }
  
  private async analyzeAndReportPatterns(): Promise<void> {
    try {
      this.logger.info('Reporting pending proactive actions...');
      
      const pendingActions = this.patternDetector.getPendingActions();
      
      this.logger.info('Proactive actions check complete', {
        pendingActions: pendingActions.length
      });
      
      if (this.ws && this.ws.readyState === WebSocket.OPEN && pendingActions.length > 0) {
        for (const action of pendingActions) {
          this.ws.send(JSON.stringify({
            type: 'proactive-action',
            timestamp: new Date().toISOString(),
            deviceId: os.hostname(),
            action: {
              actionId: action.actionId,
              patternId: action.patternId,
              title: action.title,
              description: action.description,
              reasoning: action.reasoning,
              urgency: action.urgency,
              estimatedCost: action.estimatedCost,
              estimatedDowntime: action.estimatedDowntime,
              steps: action.steps,
              preventedIssues: action.preventedIssues,
              status: action.status,
              createdAt: action.createdAt
            }
          }));
        }
        
        this.logger.info('Proactive actions sent to server', {
          count: pendingActions.length
        });
      }

      // Report hardware health scores and correlations
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        const healthScores = this.patternDetector.getHealthScores();
        const correlations = this.patternDetector.getCorrelations();

        if (Object.keys(healthScores).length > 0 || Object.keys(correlations).length > 0) {
          this.ws.send(JSON.stringify({
            type: 'hardware-health-report',
            timestamp: new Date().toISOString(),
            deviceId: os.hostname(),
            healthScores,
            correlations
          }));

          this.logger.info('Hardware health report sent to server', {
            components: Object.keys(healthScores).length,
            correlations: Object.keys(correlations).length
          });
        }
      }

    } catch (error) {
      this.logger.error('Pattern reporting failed', error);
    }
  }

  private async checkForUpdates(): Promise<void> {
    const serverUrl = this.deviceInfo.server_url || this.config.serverUrl;
    if (!serverUrl) {
      this.logger.debug('No server URL configured for updates, skipping check');
      return;
    }

    try {
      this.log('Checking for updates...');
      
      const updateUrl = `${serverUrl}/agent/update-check`;
      const currentVersion = '1.0.0';

      // Use fetch or axios instead of httpsRequest for HTTP URLs
      const response = await fetch(updateUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          currentVersion,
          platform: os.platform(),
          arch: os.arch()
        })
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json() as UpdateCheckResponse;

      if (data.updateAvailable && data.version && data.downloadUrl) {
        this.log(`Update available: ${data.version}`);
        await this.downloadAndInstallUpdate(data.downloadUrl, data.version);
      }

    } catch (error) {
      this.log('Error checking for updates', error);
    }
  }

  private async handleUpdateAvailable(version: string, downloadUrl: string): Promise<void> {
    this.log(`Server pushed update: ${version}`);
    await this.downloadAndInstallUpdate(downloadUrl, version);
  }

  private async downloadAndInstallUpdate(downloadUrl: string, version: string): Promise<void> {
    try {
      this.log(`Downloading update ${version}...`);

      const updateDir = path.join(this.dataDir, 'updates');
      if (!fs.existsSync(updateDir)) {
        fs.mkdirSync(updateDir, { recursive: true });
      }

      const installerPath = path.join(updateDir, `opsis-agent-${version}.exe`);

      await this.downloadFile(downloadUrl, installerPath);

      this.log('Update downloaded, installing...');

      await execAsync(`"${installerPath}" /S /UPDATE`);

      this.log('Update installed successfully, service will restart');

    } catch (error) {
      this.log('Error installing update', error);
    }
  }

  private downloadFile(url: string, destination: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const file = fs.createWriteStream(destination);
      
      https.get(url, { rejectUnauthorized: true }, (response) => {
        response.pipe(file);
        
        file.on('finish', () => {
          file.close();
          resolve();
        });
      }).on('error', (error) => {
        fs.unlinkSync(destination);
        reject(error);
      });
    });
  }

  private async runDiagnostic(scenario: string): Promise<void> {
    this.log(`Running diagnostic: ${scenario}`);

    const diagnosticPlaybook: PlaybookTask = {
      id: `diagnostic-${Date.now()}`,
      name: `Diagnostic: ${scenario}`,
      priority: 'high',
      source: 'server',
      createdAt: new Date(),
      steps: this.getDiagnosticSteps(scenario)
    };

    this.playbookQueue.unshift(diagnosticPlaybook);
    
    if (!this.isExecutingPlaybook) {
      this.processPlaybookQueue();
    }
  }

  private getDiagnosticSteps(scenario: string): PlaybookStep[] {
    const diagnostics: Record<string, PlaybookStep[]> = {
      'network': [
        { type: 'powershell', action: 'Test-NetConnection -ComputerName google.com', params: {} },
        { type: 'powershell', action: 'Get-NetIPConfiguration', params: {} },
        { type: 'powershell', action: 'Get-DnsClientServerAddress', params: {} }
      ],
      'disk': [
        { type: 'powershell', action: 'Get-PSDrive -PSProvider FileSystem', params: {} },
        { type: 'powershell', action: 'Get-Volume', params: {} }
      ],
      'services': [
        { type: 'powershell', action: 'Get-Service | Where-Object {$_.Status -eq "Stopped" -and $_.StartType -eq "Automatic"}', params: {} }
      ],
      'system': [
        { type: 'powershell', action: 'Get-ComputerInfo', params: {} },
        { type: 'powershell', action: 'Get-EventLog -LogName System -Newest 50 -EntryType Error', params: {} }
      ]
    };

    return diagnostics[scenario] || [];
  }

  // ============================================
  // MONITORING TRAP AGENT HELPERS
  // ============================================

  private deriveResourceId(signal: SystemSignal): string {
    if (signal.category === 'services') return `service:${signal.metadata?.serviceName || signal.id}`;
    if (signal.category === 'performance' && signal.metadata?.processName) return `process:${signal.metadata.processName}`;
    if (signal.category === 'storage') return `disk:${signal.metadata?.drive || signal.id}`;
    if (signal.category === 'network') return `network:${signal.metadata?.adapter || signal.id}`;
    return `metric:${signal.category}:${signal.metric || signal.id}`;
  }

  private deriveCurrentState(signal: SystemSignal): string {
    if (signal.category === 'services' && signal.value) return String(signal.value);
    return signal.severity;
  }

  private deriveResourceType(signal: SystemSignal): 'service' | 'process' | 'metric' | 'disk' | 'network' {
    switch (signal.category) {
      case 'services': return 'service';
      case 'storage': return 'disk';
      case 'network': return 'network';
      default: return 'metric';
    }
  }

  private checkSeverityEscalations(): void {
    const escalations = this.stateTracker.checkSeverityEscalation();
    for (const esc of escalations) {
      this.logger.warn('Severity escalated due to persistence', {
        resourceId: esc.resourceId,
        from: esc.escalatedFrom,
        to: esc.escalatedTo,
        duration_minutes: esc.durationMinutes
      });

      const resourceState = this.stateTracker.getResourceState(esc.resourceId);
      if (!resourceState) continue;

      const escalatedSignal: SystemSignal = {
        id: `escalated-${esc.resourceId}-${Date.now()}`,
        category: resourceState.resourceType === 'service' ? 'services' : 'performance',
        severity: esc.escalatedTo as 'critical' | 'warning' | 'info',
        metric: 'severity_escalation',
        value: esc.durationMinutes,
        message: `Issue persisted for ${esc.durationMinutes} minutes, severity escalated from ${esc.escalatedFrom} to ${esc.escalatedTo}`,
        timestamp: new Date(),
        metadata: {
          ...resourceState.metadata,
          escalatedFrom: esc.escalatedFrom,
          originalTimestamp: esc.originalSignalTimestamp
        }
      };

      // Process escalated signal — bypass state tracker gate since this is an internal escalation
      this.sendTelemetry(escalatedSignal);
      const signature = this.signatureGenerator.generateFromSystemSignal(escalatedSignal, this.deviceInfo);
      this.escalateToServer(signature, null);
    }
  }

  private handleMaintenanceWindowMessage(data: any): void {
    const window: MaintenanceWindow = {
      id: data.id || `mw-server-${Date.now()}`,
      name: data.name || 'Server Maintenance',
      startTime: data.start_time || data.startTime || new Date().toISOString(),
      endTime: data.end_time || data.endTime,
      scope: data.scope || { type: 'all' },
      suppressEscalation: data.suppress_escalation !== false,
      suppressRemediation: data.suppress_remediation !== false,
      createdBy: 'server',
      createdAt: new Date().toISOString()
    };

    this.maintenanceManager.addWindow(window);
    this.logger.info('Maintenance window added from server', { id: window.id, name: window.name });

    this.ipcServer.broadcast({ type: 'maintenance-window-added', data: window });
  }

  private handleCancelMaintenanceWindow(data: any): void {
    const windowId = data.id || data.window_id;
    if (windowId) {
      this.maintenanceManager.removeWindow(windowId);
      this.ipcServer.broadcast({ type: 'maintenance-window-removed', data: { id: windowId } });
    }
  }

  private createPlaybookForSystemSignal(signal: SystemSignal): PlaybookTask | null {
    const playbookId = `playbook-system-${Date.now()}`;

    if (signal.category === 'storage' && signal.metric === 'disk_free') {
      const drive = signal.metadata?.drive || 'C';
      return {
        id: playbookId,
        name: `Disk Cleanup - Drive ${drive}`,
        priority: signal.severity === 'critical' ? 'critical' : 'high',
        source: 'local',
        createdAt: new Date(),
        steps: [
          {
            type: 'powershell',
            action: `Clear-RecycleBin -DriveLetter ${drive.replace(':', '')} -Force -ErrorAction SilentlyContinue`,
            params: {}
          },
          {
            type: 'powershell',
            action: `Remove-Item "$env:TEMP\\*" -Recurse -Force -ErrorAction SilentlyContinue`,
            params: {}
          },
          {
            type: 'powershell',
            action: `Remove-Item "C:\\Windows\\Temp\\*" -Recurse -Force -ErrorAction SilentlyContinue`,
            params: {}
          },
          {
            type: 'powershell',
            action: `cleanmgr.exe /sagerun:1`,
            params: {},
            timeout: 300000
          }
        ]
      };
    }

    if (signal.category === 'services' && signal.metric === 'service_status') {
      const serviceName = signal.metadata?.serviceName;
      if (serviceName) {
        // Skip if service is suppressed (user intentionally stopped it)
        if (this.suppressedServices.has(serviceName)) {
          this.logger.info('Skipping local playbook for suppressed service', { serviceName });
          return null;
        }

        return {
          id: playbookId,
          name: `Restart Service - ${serviceName}`,
          priority: 'high',
          source: 'local',
          createdAt: new Date(),
          steps: [
            {
              type: 'service',
              action: 'start',
              params: { serviceName }
            }
          ]
        };
      }
    }

    if (signal.category === 'network' && signal.metric === 'dns_resolution') {
      return {
        id: playbookId,
        name: 'Fix DNS Issues',
        priority: 'high',
        source: 'local',
        createdAt: new Date(),
        steps: [
          {
            type: 'powershell',
            action: 'Clear-DnsClientCache',
            params: {}
          },
          {
            type: 'powershell',
            action: 'Restart-Service -Name Dnscache -Force',
            params: {}
          }
        ]
      };
    }

    return null;
  }

  private getSystemStats(): Record<string, any> {
    const metrics = this.systemMonitor.getMonitoringStats();
    
    return {
      hostname: os.hostname(),
      platform: os.platform(),
      cpus: os.cpus().length,
      totalMemory: os.totalmem(),
      freeMemory: os.freemem(),
      uptime: os.uptime(),
      monitoring: metrics
    };
  }

  private updateConfig(newConfig: Partial<AgentConfig>): void {
    this.config = { ...this.config, ...newConfig };
    this.saveConfig();
    this.logger.info('Configuration updated');
  }

  // ============================================
  // SERVER RUNBOOK STORAGE & REINVESTIGATION
  // ============================================

  /**
   * Save a successful server runbook for future local use
   */
  private saveServerRunbook(playbook: PlaybookTask): void {
    try {
      let serverRunbooks: { runbooks: Array<any>; version: string } = {
        runbooks: [],
        version: '1.0'
      };

      // Load existing server runbooks
      if (fs.existsSync(this.serverRunbooksPath)) {
        try {
          serverRunbooks = JSON.parse(fs.readFileSync(this.serverRunbooksPath, 'utf8'));
        } catch (e) {
          this.logger.warn('Failed to parse server-runbooks.json, starting fresh');
        }
      }

      // Check if runbook already exists (by ID or by similar name+steps)
      const existingIndex = serverRunbooks.runbooks.findIndex(
        (rb: any) => rb.id === playbook.id || rb.original_id === playbook.id
      );

      const runbookEntry = {
        id: `server-${playbook.id}`,
        original_id: playbook.id,
        name: playbook.name,
        source: 'server',
        priority: playbook.priority,
        steps: playbook.steps,
        saved_at: new Date().toISOString(),
        execution_count: 1,
        last_executed: new Date().toISOString(),
        success_count: 1,
        signal_id: (playbook as any).signalId,
        triggers: (playbook as any).triggers || []
      };

      if (existingIndex >= 0) {
        // Update existing entry
        const existing = serverRunbooks.runbooks[existingIndex];
        runbookEntry.execution_count = (existing.execution_count || 0) + 1;
        runbookEntry.success_count = (existing.success_count || 0) + 1;
        runbookEntry.saved_at = existing.saved_at;
        serverRunbooks.runbooks[existingIndex] = runbookEntry;

        this.logger.info('Updated server runbook', {
          id: runbookEntry.id,
          name: runbookEntry.name,
          execution_count: runbookEntry.execution_count
        });
      } else {
        serverRunbooks.runbooks.push(runbookEntry);
        this.logger.info('Saved new server runbook', {
          id: runbookEntry.id,
          name: runbookEntry.name
        });
      }

      fs.writeFileSync(this.serverRunbooksPath, JSON.stringify(serverRunbooks, null, 2), 'utf8');

      // Check if reinvestigation is needed
      if (runbookEntry.execution_count >= this.REINVESTIGATION_THRESHOLD) {
        this.escalateForReinvestigation(runbookEntry);
      }
    } catch (error) {
      this.logger.error('Failed to save server runbook', error);
    }
  }

  /**
   * Escalate to server for reinvestigation when a runbook has been executed too many times
   */
  private escalateForReinvestigation(runbookEntry: any): void {
    this.logger.warn('Runbook executed too many times, requesting reinvestigation', {
      runbook_id: runbookEntry.id,
      execution_count: runbookEntry.execution_count
    });

    const reinvestigationPayload = {
      type: 'reinvestigation_request',
      data: {
        runbook_id: runbookEntry.original_id || runbookEntry.id,
        runbook_name: runbookEntry.name,
        signal_id: runbookEntry.signal_id,
        execution_count: runbookEntry.execution_count,
        success_count: runbookEntry.success_count,
        first_seen: runbookEntry.saved_at,
        last_executed: runbookEntry.last_executed,
        device_id: os.hostname(),
        message: `Runbook "${runbookEntry.name}" has been executed ${runbookEntry.execution_count} times. Requesting reinvestigation.`
      }
    };

    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(reinvestigationPayload));
      this.logger.info('Reinvestigation request sent to server', {
        runbook_id: runbookEntry.id,
        execution_count: runbookEntry.execution_count
      });
    } else {
      this.logger.warn('Cannot send reinvestigation request - WebSocket not connected');
    }
  }

  /**
   * Handle reinvestigation response from server
   */
  private handleReinvestigationResponse(data: any): void {
    const { runbook_id, decision, diagnostic_request, new_runbook, reason } = data;

    this.logger.info('Reinvestigation response received', { runbook_id, decision, reason });

    switch (decision) {
      case 'DIAGNOSTIC':
        if (diagnostic_request) {
          this.handleDiagnosticRequest(diagnostic_request);
        }
        break;

      case 'CONTINUE_IGNORE':
        this.addToLocalIgnoreList(
          data.signal_id || runbook_id,
          reason || 'Marked as acceptable recurring issue by server'
        );
        this.logger.info('Runbook marked as acceptable recurring issue', { runbook_id });
        break;

      case 'NEW_RUNBOOK':
        if (new_runbook) {
          this.replaceServerRunbook(runbook_id, new_runbook);
          this.logger.info('Runbook replaced with new version from server', { runbook_id });
        }
        break;

      case 'PERMANENT_FIX':
        this.markRunbookAsResolved(runbook_id, reason);
        break;

      default:
        this.logger.warn('Unknown reinvestigation decision', { decision, runbook_id });
    }
  }

  /**
   * Replace an existing server runbook with a new version
   */
  private replaceServerRunbook(oldRunbookId: string, newRunbook: any): void {
    try {
      if (!fs.existsSync(this.serverRunbooksPath)) return;

      const serverRunbooks = JSON.parse(fs.readFileSync(this.serverRunbooksPath, 'utf8'));
      const index = serverRunbooks.runbooks.findIndex(
        (rb: any) => rb.id === oldRunbookId || rb.original_id === oldRunbookId
      );

      if (index >= 0) {
        const old = serverRunbooks.runbooks[index];
        serverRunbooks.runbooks[index] = {
          id: `server-${newRunbook.id}`,
          original_id: newRunbook.id,
          name: newRunbook.name,
          source: 'server',
          priority: newRunbook.priority || 'medium',
          steps: newRunbook.steps,
          saved_at: new Date().toISOString(),
          replaced_at: new Date().toISOString(),
          previous_id: old.id,
          execution_count: 0,
          success_count: 0,
          signal_id: newRunbook.signalId || old.signal_id,
          triggers: newRunbook.triggers || old.triggers || []
        };

        fs.writeFileSync(this.serverRunbooksPath, JSON.stringify(serverRunbooks, null, 2), 'utf8');
        this.logger.info('Server runbook replaced', { oldId: oldRunbookId, newId: newRunbook.id });
      }
    } catch (error) {
      this.logger.error('Failed to replace server runbook', error);
    }
  }

  /**
   * Mark a runbook as resolved (permanent fix applied)
   */
  private markRunbookAsResolved(runbookId: string, reason: string): void {
    try {
      if (!fs.existsSync(this.serverRunbooksPath)) return;

      const serverRunbooks = JSON.parse(fs.readFileSync(this.serverRunbooksPath, 'utf8'));
      const index = serverRunbooks.runbooks.findIndex(
        (rb: any) => rb.id === runbookId || rb.original_id === runbookId
      );

      if (index >= 0) {
        serverRunbooks.runbooks[index].resolved = true;
        serverRunbooks.runbooks[index].resolved_at = new Date().toISOString();
        serverRunbooks.runbooks[index].resolution_reason = reason;

        fs.writeFileSync(this.serverRunbooksPath, JSON.stringify(serverRunbooks, null, 2), 'utf8');
        this.logger.info('Runbook marked as resolved', { runbookId, reason });
      }
    } catch (error) {
      this.logger.error('Failed to mark runbook as resolved', error);
    }
  }

  /**
   * Get a saved server runbook by signal ID for local reuse
   */
  public getServerRunbookForSignal(signalId: string): any | null {
    try {
      if (!fs.existsSync(this.serverRunbooksPath)) return null;

      const serverRunbooks = JSON.parse(fs.readFileSync(this.serverRunbooksPath, 'utf8'));
      const runbook = serverRunbooks.runbooks.find(
        (rb: any) => rb.signal_id === signalId && !rb.resolved
      );

      if (runbook) {
        this.logger.debug('Found cached server runbook for signal', { signalId, runbookId: runbook.id });
        return runbook;
      }
      return null;
    } catch (error) {
      this.logger.error('Failed to get server runbook', error);
      return null;
    }
  }
}

// ============================================
// SERVICE ENTRY POINT
// ============================================

const agent = new OPSISAgentService();

process.on('SIGINT', () => {
  agent.stop();
  process.exit(0);
});

process.on('SIGTERM', () => {
  agent.stop();
  process.exit(0);
});

agent.start().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});

export default OPSISAgentService;
