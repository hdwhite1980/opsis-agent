// agent-service.ts - Production OPSIS Agent Service with Tiered Intelligence Integration
import * as os from 'os';
import * as fs from 'fs';
import * as path from 'path';
import * as https from 'https';
import * as crypto from 'crypto';
import { exec, spawn } from 'child_process';
import { promisify } from 'util';
import WebSocket from 'ws';
import { getServiceLogger, Logger } from '../common/logger';
import EventMonitor, { EventLogEntry, RunbookMatch, Runbook } from './event-monitor';
import { TicketDatabase, Ticket } from './ticket-database';
import { SystemMonitor, SystemSignal } from './system-monitor';
import { IPCServer } from './ipc-server';
import { RemediationMemory } from './remediation-memory';

import { PatternDetector } from './pattern-detector';

// NEW IMPORTS - Tiered Intelligence Components
import { SignatureGenerator, DeviceSignature } from './signature-generator';
import { EscalationProtocol, EscalationPayload, ServerDecision } from './escalation-protocol';
import { RunbookClassifier, RiskClass } from './runbook-classifier';
import { ActionTicketManager } from './action-ticket-manager';
import { TroubleshootingRunner, DiagnosticData } from './troubleshooting-runner';
import { StateTracker, StateChangeEvent, SeverityEscalationEvent } from './state-tracker';
import { MaintenanceWindowManager, MaintenanceWindow } from './maintenance-windows';
import { SelfServiceServer } from './self-service-server';
import { ControlPanelServer } from './control-panel-server';
import { BaselineManager } from './baseline-manager';
import { BehavioralProfiler } from './behavioral-profiler';
import { SignalCorrelator, CorrelationResult } from './signal-correlator';
import { CompatibilityChecker, CompatibilityReport, CapabilityMode } from './compatibility-checker';

import { updateServerProtections, updateLearnedProtections } from '../execution/primitives/index';

// Security imports
import {
  getApiKey,
  getHmacSecret,
  storeHmacSecret,
  storeCredentialsFromSetup,
  verifyPlaybook,
  verifyDiagnosticRequest,
  validatePlaybook,
  validateDiagnosticRequest,
  handleKeyRotation,
  createRotationAck,
  createRotationError,
  isHmacConfigured,
  tryParseJSON,
  registerRunbookHash,
  verifyRunbookIntegrity,
  canonicalizeServerRunbook,
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

interface FallbackChain {
  trigger: 'step_failure';
  condition?: {
    failed_step_index?: number;
    failed_step_type?: string;
    error_pattern?: string;
  };
  fallback_steps: PlaybookStep[];
  max_attempts?: number; // default 1
}

interface PlaybookTask {
  id: string;
  name: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
  source: 'server' | 'admin' | 'local';
  steps: PlaybookStep[];
  fallback_chains?: FallbackChain[];
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
  private recentSignatureIds: string[] = []; // Track recent signature_ids for linking server playbooks
  private pendingRebootCompletedMsg: any = null; // Queued reboot_completed message to send on WS connect
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
  private readonly pendingRebootPlaybookPath: string;
  private readonly REINVESTIGATION_THRESHOLD = 10; // Escalate for reinvestigation after 10 executions

  // Server-provided configuration (received via welcome message)
  private serverConfig: ServerConfig | null = null;
  private heartbeatTimer: NodeJS.Timeout | null = null;
  private welcomeTimeout: NodeJS.Timeout | null = null;
  private telemetryTimer: NodeJS.Timeout | null = null;
  private inventoryTimer: NodeJS.Timeout | null = null;

  // Adaptive telemetry interval (Enhancement 11)
  private telemetryMode: 'normal' | 'reduced' | 'minimal' = 'normal';
  private currentHeartbeatIntervalMs: number = 30000;
  private lastSignalTime: number = Date.now();
  private serverFixedHeartbeatInterval: number | null = null; // If set, disables adaptive mode
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

  // Self-service portal
  private selfServiceServer: SelfServiceServer | null = null;

  // Control panel web server
  private controlPanelServer: ControlPanelServer | null = null;

  // System baseline manager
  private baselineManager: BaselineManager;

  // Behavioral profiler for temporal anomaly detection
  private behavioralProfiler: BehavioralProfiler;
  private signalCorrelator: SignalCorrelator;

  // Compatibility checker and capability mode
  private compatibilityChecker: CompatibilityChecker;
  private capabilityMode: CapabilityMode = 'full';
  private compatibilityReport: CompatibilityReport | null = null;

  // Protected applications (server-pushed, scoped by client)
  private protectedApplications: Array<{
    process_name?: string;
    service_name?: string;
    display_name: string;
  }> = [];

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
    this.pendingRebootPlaybookPath = path.join(this.dataDir, 'pending-reboot-playbook.json');
    this.pendingActionsPath = path.join(this.dataDir, 'pending-actions.json');

    // Ensure directories exist
    [this.dataDir, this.logsDir, this.runbooksDir].forEach(dir => {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
    });

    // Initialize logger
    this.logger = getServiceLogger(this.logsDir);
    
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

    // Initialize behavioral profiler for temporal anomaly detection
    this.behavioralProfiler = new BehavioralProfiler(this.dataDir, this.logger);
    this.signalCorrelator = new SignalCorrelator(this.logger);
    this.systemMonitor.setProfiler(this.behavioralProfiler);

    // Initialize IPC server for GUI communication
    this.ipcServer = new IPCServer(this.logger);
    this.setupIPCHandlers();

    // Initialize baseline manager (before self-service portal which depends on it)
    this.baselineManager = new BaselineManager(this.logger, this.dataDir);

    // Initialize self-service portal
    this.selfServiceServer = new SelfServiceServer(
      this.logger,
      this.troubleshootingRunner,
      this.actionTicketManager,
      this.ticketDb,
      this.baseDir,
      19850,
      this.baselineManager
    );

    // Initialize control panel web server
    this.controlPanelServer = new ControlPanelServer(this.logger, this.baseDir, 19851);
    this.controlPanelServer.onRequest = async (type: string, data: any) => {
      return this.handleControlPanelRequest(type, data);
    };
    this.controlPanelServer.onClientConnected = (sendFn) => {
      try {
        sendFn(this.buildInitialData());
      } catch (error) {
        this.logger.error('Error sending initial data to control panel', error);
      }
    };

    // Initialize compatibility checker
    this.compatibilityChecker = new CompatibilityChecker(this.logger);

    // Send initial data when GUI connects
    this.ipcServer.onClientConnected((socket) => {
      try {
        this.ipcServer.sendToClient(socket, this.buildInitialData());
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
        let data = fs.readFileSync(this.configPath, 'utf8');
        // Strip UTF-8 BOM if present (PowerShell can write these)
        if (data.charCodeAt(0) === 0xFEFF) {
          data = data.slice(1);
        }
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
    
    this.broadcastToAllClients({
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

  /** Broadcast to both IPC and web control panel clients */
  private broadcastToAllClients(message: { type: string; data: any }): void {
    this.ipcServer.broadcast(message);
    if (this.controlPanelServer) {
      this.controlPanelServer.broadcast(message);
    }
  }

  /** Check if any GUI client is connected (IPC or web) */
  private hasAnyGuiClient(): boolean {
    return this.ipcServer.hasAuthenticatedClients() ||
      (this.controlPanelServer?.hasConnectedClients() ?? false);
  }

  /** Build the initial-data payload sent when a GUI client connects */
  private buildInitialData(): { type: string; data: any } {
    const tickets = this.ticketDb.getTickets(100);
    const stats = this.ticketDb.getStatistics();
    return {
      type: 'initial-data',
      data: {
        tickets,
        stats: {
          issuesDetected: stats.totalTickets,
          issuesEscalated: stats.escalatedTickets,
          successRate: stats.successRate,
          activeTickets: stats.openTickets
        },
        healthScores: this.patternDetector.getHealthScores(),
        correlations: this.patternDetector.getCorrelations(),
        patterns: this.patternDetector.getDetectedPatterns(),
        proactiveActions: this.patternDetector.getPendingActions(),
        serviceAlerts: this.serviceAlerts,
        capabilityMode: this.capabilityMode,
        deploymentHealth: this.compatibilityReport,
        protectedApplications: this.protectedApplications,
        exclusions: this.loadExclusionsFile(),
        ignoreList: this.loadIgnoreListFile()
      }
    };
  }

  /** Handle a control panel WebSocket request and return the response */
  private async handleControlPanelRequest(type: string, data: any): Promise<{ type: string; data: any } | null> {
    switch (type) {
      case 'get-tickets': {
        const tickets = this.ticketDb.getTickets(100);
        const stats = this.ticketDb.getStatistics();
        return { type: 'tickets', data: { tickets, stats: {
          issuesDetected: stats.totalTickets, issuesEscalated: stats.escalatedTickets,
          successRate: stats.successRate, activeTickets: stats.openTickets
        } } };
      }
      case 'get-status':
        return { type: 'status', data: this.getSystemStats() };
      case 'get-stats': {
        const ticketStats = this.ticketDb.getStatistics();
        return { type: 'stats', data: {
          issuesDetected: ticketStats.totalTickets, issuesEscalated: ticketStats.escalatedTickets,
          successRate: ticketStats.successRate, activeTickets: ticketStats.openTickets
        } };
      }
      case 'get-health-data':
        return { type: 'health-data', data: {
          healthScores: this.patternDetector.getHealthScores(),
          correlations: this.patternDetector.getCorrelations(),
          patterns: this.patternDetector.getDetectedPatterns(),
          proactiveActions: this.patternDetector.getPendingActions()
        } };
      case 'get-ticket':
        return { type: 'ticket-details', data: this.ticketDb.getTicket(data.ticketId) };
      case 'get-memory-stats': {
        const summary = this.remediationMemory.getSummary();
        const memoryData = this.remediationMemory.exportData();
        return { type: 'memory-stats', data: {
          summary,
          dampenedSignals: Object.values(memoryData.signalStats).filter((s: any) => s.dampened),
          topFailingPlaybooks: Object.values(memoryData.playbookStats)
            .filter((p: any) => p.totalAttempts >= 3 && p.successRate < 0.5)
            .sort((a: any, b: any) => a.successRate - b.successRate).slice(0, 10),
          deviceSensitivity: Object.values(memoryData.deviceSensitivity)
        } };
      }
      case 'reset-dampening':
        this.remediationMemory.resetDampening(data.signalId, data.deviceId);
        return { type: 'dampening-reset', data: { success: true, signalId: data.signalId, deviceId: data.deviceId } };
      case 'get-service-alerts':
        return { type: 'service-alerts', data: this.serviceAlerts };
      case 'dismiss-alert':
        this.serviceAlerts = this.serviceAlerts.filter(a => a.id !== data.alertId);
        return null;
      case 'update-config':
        this.updateConfig(data);
        return { type: 'config-updated', data: { success: true } };
      case 'update-settings':
        this.updateConfig(data);
        return { type: 'settings-updated', data: { success: true } };
      case 'get-settings': {
        try {
          const configContent = fs.readFileSync(this.configPath, 'utf-8');
          return { type: 'settings', data: JSON.parse(configContent) };
        } catch {
          return { type: 'settings', data: {} };
        }
      }
      case 'clear-old-tickets': {
        const count = this.ticketDb.deleteOldTickets(1);
        this.broadcastTicketUpdate();
        return { type: 'clear-old-tickets-result', data: count };
      }
      case 'clear-all-tickets': {
        const count = this.ticketDb.deleteAllTickets();
        this.broadcastTicketUpdate();
        return { type: 'clear-all-tickets-result', data: { deleted: count } };
      }
      case 'user-prompt-response': {
        const { promptId, response } = data;
        const pending = this.pendingPrompts.get(promptId);
        if (pending) {
          if (pending.timer) clearTimeout(pending.timer);
          this.pendingPrompts.delete(promptId);
          if (response === 'ok' && pending.action_on_confirm === 'reboot') {
            const { exec } = require('child_process');
            exec('shutdown /r /t 30 /c "OPSIS Agent: Restarting to complete remediation"', (err: any) => {
              if (err) this.logger.error('Failed to initiate reboot', err);
            });
          }
          pending.resolve(response);
          if (this.ws && this.ws.readyState === 1) {
            this.ws.send(JSON.stringify({
              type: 'user-prompt-response', prompt_id: promptId, response,
              device_id: this.deviceInfo.device_id, timestamp: new Date().toISOString()
            }));
          }
        }
        return null;
      }
      case 'suppress-service': {
        const { serviceName } = data;
        if (!OPSISAgentService.SAFE_TO_STOP_SERVICES.has(serviceName)) {
          return { type: 'suppress-service-result', data: { success: false, error: `Service '${serviceName}' is not safe to stop` } };
        }
        try {
          await execAsync(`powershell -NoProfile -Command "Stop-Service -Name '${serviceName}' -Force"`, { timeout: 30000 });
          this.suppressedServices.add(serviceName);
          return { type: 'suppress-service-result', data: { success: true, serviceName, status: 'stopped_and_suppressed' } };
        } catch (error: any) {
          return { type: 'suppress-service-result', data: { success: false, error: error.message } };
        }
      }
      case 'unsuppress-service': {
        const { serviceName: svcName, startService } = data;
        this.suppressedServices.delete(svcName);
        if (startService) {
          try {
            await execAsync(`powershell -NoProfile -Command "Start-Service -Name '${svcName}'"`, { timeout: 30000 });
            return { type: 'unsuppress-service-result', data: { success: true, serviceName: svcName, status: 'unsuppressed_and_started' } };
          } catch (error: any) {
            return { type: 'unsuppress-service-result', data: { success: true, serviceName: svcName, status: 'unsuppressed_but_start_failed', error: error.message } };
          }
        }
        return { type: 'unsuppress-service-result', data: { success: true, serviceName: svcName, status: 'unsuppressed' } };
      }
      case 'get-suppressed-services':
        return { type: 'suppressed-services', data: {
          services: Array.from(this.suppressedServices),
          safeServices: Array.from(OPSISAgentService.SAFE_TO_STOP_SERVICES)
        } };
      case 'get-pending-actions': {
        const actions = Array.from(this.pendingActions.entries()).map(([id, action]) => ({
          signature_id: id, ticket_id: action.ticket_id,
          runbook_name: action.runbook?.name, server_message: action.server_message,
          created_at: action.created_at, signature_name: action.signature.signature_id,
          severity: action.signature.severity
        }));
        return { type: 'pending-actions', data: { actions } };
      }
      case 'execute-pending-action':
        if (data.signature_id && this.pendingActions.has(data.signature_id)) {
          this.executePendingAction(data.signature_id);
          return { type: 'execute-pending-action-result', data: { success: true, signature_id: data.signature_id } };
        }
        return { type: 'execute-pending-action-result', data: { success: false, signature_id: data.signature_id, error: 'Pending action not found' } };
      case 'cancel-pending-action':
        if (data.signature_id && this.pendingActions.has(data.signature_id)) {
          this.cancelPendingAction(data.signature_id, data.reason);
          return { type: 'cancel-pending-action-result', data: { success: true, signature_id: data.signature_id } };
        }
        return { type: 'cancel-pending-action-result', data: { success: false, signature_id: data.signature_id, error: 'Pending action not found' } };
      case 'submit-manual-ticket': {
        try {
          const ticketId = `manual-${Date.now()}`;
          const ticket = {
            ticket_id: ticketId, timestamp: data.submittedAt || new Date().toISOString(),
            type: 'manual-investigation',
            description: `[${data.category}] ${data.description} (Server: ${data.serverName}, Priority: ${data.priority})`,
            status: 'open' as const, source: 'manual' as const,
            computer_name: data.serverName || os.hostname(), escalated: 1,
            diagnostic_summary: `User-reported issue: ${data.category}\n${data.description}`,
            recommended_action: 'Submitted for manual investigation',
            resolution_category: 'escalated' as const
          };
          this.ticketDb.createTicket(ticket);
          this.ticketDb.markAsEscalated(ticketId);
          this.broadcastTicketUpdate();
          return { type: 'submit-manual-ticket-result', data: { success: true, ticketId } };
        } catch (error: any) {
          return { type: 'submit-manual-ticket-result', data: { success: false, error: error.message } };
        }
      }
      case 'test-escalation': {
        const issueType = data.type || 'disk-space-low';
        const testSignature: DeviceSignature = {
          signature_id: `test-${Date.now()}-${Math.random().toString(36).substring(7)}`,
          tenant_id: this.deviceInfo.tenant_id, device_id: this.deviceInfo.device_id,
          timestamp: new Date().toISOString(), severity: data.severity || 'medium',
          confidence_local: data.confidence || 65, symptoms: [], targets: [],
          context: { os_build: os.release(), os_version: `Windows ${os.release()}`, device_role: this.deviceInfo.role || 'workstation' }
        };
        this.escalateToServer(testSignature, null);
        return { type: 'test-escalation-result', data: { success: true, signature_id: testSignature.signature_id, issue_type: issueType, message: 'Test escalation sent to server' } };
      }
      case 'create-maintenance-window': {
        const mw: MaintenanceWindow = {
          id: `mw-gui-${Date.now()}`, name: data.name || 'Maintenance Window',
          startTime: data.startTime || new Date().toISOString(), endTime: data.endTime,
          scope: data.scope || { type: 'all' }, suppressEscalation: data.suppressEscalation !== false,
          suppressRemediation: data.suppressRemediation !== false, createdBy: 'technician',
          createdAt: new Date().toISOString()
        };
        this.maintenanceManager.addWindow(mw);
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
          this.ws.send(JSON.stringify({ type: 'maintenance_window_created', data: mw }));
        }
        return { type: 'maintenance-window-created', data: { success: true, window: mw } };
      }
      case 'cancel-maintenance-window':
        this.maintenanceManager.removeWindow(data.id);
        return { type: 'maintenance-window-cancelled', data: { success: true, id: data.id } };
      case 'get-maintenance-windows':
        return { type: 'maintenance-windows', data: {
          all: this.maintenanceManager.getAllWindows(),
          active: this.maintenanceManager.getActiveWindows()
        } };
      case 'get-state-tracker-summary':
        return { type: 'state-tracker-summary', data: this.stateTracker.getSummary() };
      case 'get-exclusions':
        return { type: 'exclusions', data: this.loadExclusionsFile() };
      case 'get-ignore-list':
        return { type: 'ignore-list', data: this.loadIgnoreListFile() };
      case 'get-protected-applications':
        return { type: 'protected-applications', data: this.protectedApplications };
      default:
        this.logger.warn('Unknown control panel request type', { type });
        return null;
    }
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
   * Run full compatibility check, determine capability mode, and log results.
   * Replaces the old detectPolicyRestrictions() with comprehensive checks.
   */
  private async detectPolicyRestrictions(): Promise<void> {
    this.compatibilityReport = await this.compatibilityChecker.runFullCheck();
    this.capabilityMode = this.compatibilityReport.capability_mode;

    // Log each check result
    for (const check of this.compatibilityReport.checks) {
      if (check.status === 'red') {
        this.logger.warn(`[COMPAT] ${check.name}: ${check.detail}`, { impact: check.impact });
      } else if (check.status === 'yellow') {
        this.logger.warn(`[COMPAT] ${check.name}: ${check.detail}`, { impact: check.impact });
      } else {
        this.logger.info(`[COMPAT] ${check.name}: ${check.detail}`);
      }
    }

    if (this.capabilityMode !== 'full') {
      this.logger.warn(`Agent operating in ${this.capabilityMode.toUpperCase()} mode`, {
        disabled_categories: this.compatibilityReport.disabled_categories
      });
    }
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

    // Start self-service portal
    if (this.selfServiceServer) {
      await this.selfServiceServer.start();
      this.selfServiceServer.onResolution = (data) => this.reportSelfServiceResolution(data);
      this.log(`Self-service portal started on http://localhost:${this.selfServiceServer.getPort()}`);
    }

    // Start control panel web server
    if (this.controlPanelServer) {
      await this.controlPanelServer.start();
      this.log(`Control panel started on http://localhost:${this.controlPanelServer.getPort()}`);
    }

    // Load pending actions from disk
    this.loadPendingActions();

    // Load protected applications from local config
    this.loadProtectedApplications();

    // Resume any playbook interrupted by a reboot
    await this.resumeRebootPlaybook();

    // Start event monitoring
    this.eventMonitor.startMonitoring(30);
    this.log('Event monitoring started');

    // Start system monitoring
    this.systemMonitor.start();
    this.log('System monitoring started (60 second intervals)');

    // Initialize baseline health scores for hardware components
    await this.patternDetector.initializeBaselineHealthScores();
    this.log('Hardware health scores initialized');

    // Capture system baseline (first run or refresh after 24h)
    await this.baselineManager.captureIfNeeded();
    this.log('System baseline check complete');

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
      this.stateTracker.refreshDependencyMap().then(() => {
        // Update tier 3 auto-learned protections from dependency graph
        const depMap = this.stateTracker.getDependencyMap();
        updateLearnedProtections(depMap);
      }).catch(err =>
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

    // Periodically check if telemetry mode should change (every 60s)
    setInterval(() => this.updateTelemetryMode(), 60000);

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

  public async stop(): Promise<void> {
    this.log('OPSIS Agent Service Stopping...');

    if (this.selfServiceServer) {
      this.selfServiceServer.stop();
    }

    if (this.controlPanelServer) {
      this.controlPanelServer.stop();
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

    if (this.inventoryTimer) {
      clearInterval(this.inventoryTimer);
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

    // Flush and stop behavioral profiler
    if (this.behavioralProfiler) {
      await this.behavioralProfiler.flush();
      this.behavioralProfiler.stop();
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

      this.ws.on('open', async () => {
        this.log('Connected to OPSIS server, sending registration...');
        this.reconnectAttempts = 0; // Reset backoff on successful connection

        // Collect system info for registration
        const systemInfo = await this.collectSystemInfo();

        // Send registration immediately — don't wait for welcome
        this.ws!.send(JSON.stringify({
          type: 'register',
          device_id: this.deviceInfo.device_id,
          tenant_id: this.deviceInfo.tenant_id,
          hostname: os.hostname(),
          agent_version: '1.0.0',
          os: `${os.platform()} ${os.release()}`,
          timestamp: new Date().toISOString(),
          system_info: systemInfo,
          capability_mode: this.capabilityMode,
          deployment_health: this.compatibilityReport
        }));

        // Send pending reboot_completed notification if resuming after reboot
        if (this.pendingRebootCompletedMsg) {
          this.ws!.send(JSON.stringify(this.pendingRebootCompletedMsg));
          this.logger.info('Sent reboot_completed to server', {
            playbook_id: this.pendingRebootCompletedMsg.playbook_id,
            authorized_by: this.pendingRebootCompletedMsg.authorized_by,
            downtime_seconds: this.pendingRebootCompletedMsg.downtime_seconds
          });
          this.pendingRebootCompletedMsg = null;
        }

        // Start heartbeat immediately with adaptive interval
        // (will be updated if welcome arrives with custom config)
        if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
        this.telemetryMode = 'normal'; // Start in normal mode on new connection
        this.currentHeartbeatIntervalMs = 30000;
        this.lastSignalTime = Date.now();
        this.sendHeartbeat();
        this.heartbeatTimer = setInterval(() => this.sendHeartbeat(), 30000);

        // Send software inventory on connect, then hourly
        if (this.inventoryTimer) clearInterval(this.inventoryTimer);
        // Delay initial inventory by 10s to let connection stabilize
        setTimeout(() => this.sendSoftwareInventory(), 10000);
        this.inventoryTimer = setInterval(() => this.sendSoftwareInventory(), 3600000);

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
        type: 'signal',
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

  private async sendHeartbeat(): Promise<void> {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;

    try {
      // Collect real-time metrics for flat telemetry format
      const [cpuPercent, diskStats, processCount] = await Promise.all([
        this.systemMonitor.getCPUUsage(),
        this.systemMonitor.getDiskStats(),
        this.systemMonitor.getProcessCount()
      ]);

      const totalMem = os.totalmem();
      const freeMem = os.freemem();
      const usedMem = totalMem - freeMem;
      const memPercent = Math.round((usedMem / totalMem) * 1000) / 10;
      const memUsedMB = Math.round(usedMem / 1024 / 1024);
      const memAvailableMB = Math.round(freeMem / 1024 / 1024);

      const ticketStats = this.ticketDb.getStatistics();

      // Send flat telemetry format
      this.ws.send(JSON.stringify({
        type: 'telemetry',
        timestamp: new Date().toISOString(),
        device_id: this.deviceInfo.device_id,
        tenant_id: this.deviceInfo.tenant_id,
        cpu_percent: Math.round(cpuPercent * 10) / 10,
        memory_percent: memPercent,
        memory_used_mb: memUsedMB,
        memory_available_mb: memAvailableMB,
        disk_percent: diskStats.usedPercent,
        disk_free_gb: diskStats.freeGB,
        active_issues: ticketStats.openTickets,
        process_count: processCount,
        capability_mode: this.capabilityMode,
        ntp_sync_ok: this.systemMonitor.isNtpSyncOk(),
        telemetry_mode: this.telemetryMode,
        heartbeat_interval_ms: this.serverFixedHeartbeatInterval || this.currentHeartbeatIntervalMs,
        ewma_scores: this.patternDetector.getEWMAScores(),
        discovered_correlations: this.patternDetector.getDiscoveredCorrelations(),
        behavioral_profile: this.behavioralProfiler.getDashboardSummary()
      }));
    } catch (error) {
      this.logger.error('Failed to send telemetry heartbeat', error);
    }
  }

  /**
   * Adaptive telemetry interval (Enhancement 11).
   * Adjusts heartbeat interval based on system activity:
   * - normal:  30s (open tickets, recent signals, or profiler learning)
   * - reduced: 60s (no tickets, 5-10 min since last signal)
   * - minimal: 180s (no tickets, 10+ min since last signal, profiler active)
   */
  private updateTelemetryMode(): void {
    // Server can override with a fixed interval — disables adaptive mode
    if (this.serverFixedHeartbeatInterval) return;

    const now = Date.now();
    const timeSinceSignal = now - this.lastSignalTime;
    const ticketStats = this.ticketDb.getStatistics();
    const hasOpenTickets = ticketStats.openTickets > 0;
    const profilerStatus = this.behavioralProfiler.getDashboardSummary().status;

    let newMode: 'normal' | 'reduced' | 'minimal';

    if (hasOpenTickets || timeSinceSignal < 5 * 60 * 1000 || profilerStatus === 'learning') {
      newMode = 'normal';
    } else if (timeSinceSignal < 10 * 60 * 1000) {
      newMode = 'reduced';
    } else {
      newMode = 'minimal';
    }

    if (newMode !== this.telemetryMode) {
      const oldMode = this.telemetryMode;
      this.telemetryMode = newMode;

      const intervals: Record<typeof newMode, number> = { normal: 30000, reduced: 60000, minimal: 180000 };
      const newInterval = intervals[newMode];
      this.currentHeartbeatIntervalMs = newInterval;

      // Restart heartbeat timer with new interval
      if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = setInterval(() => this.sendHeartbeat(), newInterval);

      this.logger.info('Telemetry mode changed', { from: oldMode, to: newMode, interval_ms: newInterval });
    }
  }

  /** Record that a signal was detected and send an immediate heartbeat */
  private recordSignalForTelemetry(): void {
    this.lastSignalTime = Date.now();
    this.updateTelemetryMode();
    // Send an immediate heartbeat when a signal is detected
    this.sendHeartbeat();
  }

  private async sendSoftwareInventory(): Promise<void> {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;

    try {
      this.logger.info('Collecting software inventory...');
      const software = await this.systemMonitor.getSoftwareInventory();

      this.ws.send(JSON.stringify({
        type: 'software_inventory',
        timestamp: new Date().toISOString(),
        device_id: this.deviceInfo.device_id,
        tenant_id: this.deviceInfo.tenant_id,
        software
      }));

      this.logger.info('Software inventory sent', { count: software.length });
    } catch (error) {
      this.logger.error('Failed to send software inventory', error);
    }
  }

  // UPDATED: Handle server messages including decisions
  private async handleServerMessage(message: string): Promise<void> {
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
          
        case 'playbook': {
          // Server may send playbook nested under data.playbook or as the root object itself
          const playbook = data.playbook || data;

          // SECURITY: Verify HMAC signature BEFORE any mutation/normalization
          if (playbook._signature) {
            const verification = await verifyPlaybook(playbook);
            if (!verification.valid) {
              this.logger.error(`Playbook signature verification failed: ${verification.error}`, {
                playbookId: playbook.playbook_id || playbook.id,
                hasTimestamp: !!playbook._timestamp,
                hasNonce: !!playbook._nonce
              });
              break; // Reject
            }
            this.logger.info('Playbook signature verified', { playbookId: playbook.playbook_id || playbook.id });
          } else {
            const hmacRequired = await isHmacConfigured();
            if (hmacRequired) {
              this.logger.error('SECURITY: Server playbook missing signature, rejecting', {
                playbookId: playbook.playbook_id || playbook.id
              });
              break;
            }
          }

          // Normalize server field names: playbook_id -> id, title -> name
          if (!playbook.id && playbook.playbook_id) playbook.id = playbook.playbook_id;
          if (!playbook.name && playbook.title) playbook.name = playbook.title;
          if (!playbook || !playbook.id) {
            this.logger.warn('Received playbook message with no valid playbook data', { raw: JSON.stringify(data).slice(0, 500) });
            break;
          }
          // Tag playbook with the most recent signature_id for cache linking
          if (this.recentSignatureIds.length > 0) {
            playbook.signatureId = this.recentSignatureIds[0];
          }
          this.receivePlaybook(playbook, 'server');
          break;
        }
          
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
          // Handle protected applications list from server
          if (data.protected_applications) {
            this.saveProtectedApplications(data.protected_applications);
            // Update tier 2 protections in primitives
            const serverProcesses = data.protected_applications
              .filter((a: any) => a.process_name).map((a: any) => a.process_name);
            const serverServices = data.protected_applications
              .filter((a: any) => a.service_name).map((a: any) => a.service_name);
            updateServerProtections(serverProcesses, serverServices);
          }
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

        case 'self_service_response':
          // AI escalation response for self-service portal
          if (this.selfServiceServer && data.session_id) {
            this.selfServiceServer.handleEscalationResponse(data.session_id, data);
          }
          break;

        case 'baseline_capture':
          this.handleBaselineCapture(data);
          break;

        case 'baseline_stored':
          this.logger.info('Server confirmed baseline stored', {
            status: data.status,
            baseline_name: data.baseline_name,
            summary: data.summary
          });
          this.broadcastToAllClients({
            type: 'baseline-stored',
            data: { status: data.status, baseline_name: data.baseline_name, summary: data.summary }
          });
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
    if (this.hasAnyGuiClient()) {
      this.broadcastToAllClients({
        type: 'service-alert',
        data: alert
      });
    } else {
      // No GUI connected — log only, no popup (suppresses Windows Script Host dialogs)
      this.logger.info('No GUI connected, service alert logged only', {
        id: alert.id,
        service: alert.service,
        severity: alert.severity,
        message: alert.message || alert.description
      });
    }
  }

  // Handle service alert resolution
  private handleServiceAlertResolved(data: any): void {
    const alertId = data?.id || data?.alertId;
    if (!alertId) return;

    this.logger.info('Service alert resolved', { id: alertId });
    this.serviceAlerts = this.serviceAlerts.filter(a => a.id !== alertId);

    this.broadcastToAllClients({
      type: 'service-alert-resolved',
      data: { id: alertId }
    });
  }

  /**
   * Handle baseline_capture message from server.
   * Writes the server-provided PowerShell script to a temp file,
   * executes it, parses the JSON output, and sends baseline_result back.
   */
  private async handleBaselineCapture(message: any): Promise<void> {
    this.logger.info('Baseline capture requested by server');

    const script = message.script;
    if (!script) {
      this.logger.error('No capture script in baseline_capture message');
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({
          type: 'baseline_result',
          status: 'error',
          error: 'No capture script provided'
        }));
      }
      return;
    }

    const scriptPath = path.join(os.tmpdir(), 'opsis_baseline_capture.ps1');

    try {
      // Write script to temp file
      fs.writeFileSync(scriptPath, script, 'utf8');
      this.logger.info('Baseline script written to temp file', { path: scriptPath });

      // Notify control panel that capture is in progress
      this.broadcastToAllClients({
        type: 'baseline-progress',
        data: { status: 'running', message: 'Capturing system baseline...' }
      });

      // Execute PowerShell with extended timeout (2 minutes)
      const output = await this.runPowerShellScript(scriptPath, 120000);

      // Clean up temp file
      try { fs.unlinkSync(scriptPath); } catch (_) { /* ignore */ }

      // Parse the JSON output — script outputs a single JSON blob
      let baselineData: any;
      try {
        const lines = output.trim().split('\n');
        let jsonLine = '';
        for (let i = lines.length - 1; i >= 0; i--) {
          const line = lines[i].trim();
          if (line.startsWith('{')) {
            jsonLine = line;
            break;
          }
        }
        if (!jsonLine) {
          throw new Error('No JSON found in script output');
        }
        baselineData = JSON.parse(jsonLine);
      } catch (parseErr: any) {
        this.logger.error('Failed to parse baseline output', { error: parseErr.message });
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
          this.ws.send(JSON.stringify({
            type: 'baseline_result',
            status: 'error',
            error: `Parse failed: ${parseErr.message}`,
            raw_output: output.substring(0, 2000)
          }));
        }
        return;
      }

      const swCount = (baselineData.installed_software || []).length;
      const prCount = (baselineData.printers || []).length;
      const drCount = (baselineData.mapped_drives || []).length;
      const svcCount = (baselineData.running_services || []).length;

      this.logger.info('Baseline capture complete', {
        software: swCount, printers: prCount, mapped_drives: drCount, services: svcCount
      });

      // Send results back to server
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({
          type: 'baseline_result',
          status: 'success',
          baseline_name: message.baseline_name || 'auto',
          is_template: message.is_template || false,
          template_name: message.template_name || null,
          notes: message.notes || null,
          data: baselineData
        }));
      }

      // Notify control panel
      this.broadcastToAllClients({
        type: 'baseline-captured',
        data: {
          status: 'complete',
          baseline_name: message.baseline_name,
          summary: { software: swCount, printers: prCount, mapped_drives: drCount, services: svcCount }
        }
      });

    } catch (err: any) {
      this.logger.error('Baseline capture failed', { error: err.message });
      try { fs.unlinkSync(scriptPath); } catch (_) { /* ignore */ }

      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({
          type: 'baseline_result',
          status: 'error',
          error: err.message
        }));
      }

      this.broadcastToAllClients({
        type: 'baseline-captured',
        data: { status: 'failed', error: err.message }
      });
    }
  }

  /**
   * Run a PowerShell script file and return stdout.
   */
  private runPowerShellScript(scriptPath: string, timeoutMs: number = 120000): Promise<string> {
    return new Promise((resolve, reject) => {
      const args = ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', scriptPath];

      const proc = spawn('powershell.exe', args, {
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe']
      });

      let stdout = '';
      let stderr = '';

      proc.stdout.on('data', (data: Buffer) => { stdout += data.toString(); });
      proc.stderr.on('data', (data: Buffer) => { stderr += data.toString(); });

      const timer = setTimeout(() => {
        proc.kill('SIGTERM');
        reject(new Error(`Baseline script timed out after ${timeoutMs / 1000}s`));
      }, timeoutMs);

      proc.on('close', (code: number | null) => {
        clearTimeout(timer);
        if (code === 0 || stdout.includes('"system"')) {
          resolve(stdout);
        } else {
          reject(new Error(`PowerShell exited with code ${code}: ${stderr.substring(0, 500)}`));
        }
      });

      proc.on('error', (err: Error) => {
        clearTimeout(timer);
        reject(err);
      });
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

    if (this.hasAnyGuiClient()) {
      // GUI is connected — broadcast via IPC + web
      this.broadcastToAllClients({
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
    } else {
      // No GUI connected — fall back to native Windows dialog
      this.logger.info('No GUI connected, using native Windows prompt for server user-prompt');
      const { spawnSync } = require('child_process');
      const title = String(promptData.title || 'Action Required').replace(/'/g, "''").replace(/[`$&|;<>\r\n"]/g, '');
      const msg = String(promptData.message || '').replace(/'/g, "''").replace(/[`$&|;<>\r\n"]/g, '');
      const buttons = promptData.buttons || ['OK', 'Cancel'];
      // Map button labels to WPF button enum
      const hasCancel = buttons.some((b: string) => /cancel|no|later|decline/i.test(b));
      const wpfButtons = hasCancel ? 'YesNo' : 'OK';
      const psScript = `Add-Type -AssemblyName PresentationFramework; $result = [System.Windows.MessageBox]::Show('${msg}', 'OPSIS Agent - ${title}', '${wpfButtons}', 'Information'); Write-Output $result`;
      const result = spawnSync('powershell.exe', ['-NoProfile', '-Command', psScript], { timeout: (promptData.timeout || 300) * 1000 });
      const output = result.stdout ? result.stdout.toString().trim() : 'timeout';
      this.logger.info('Native user-prompt result', { promptId, result: output });

      // Resolve the pending prompt
      clearTimeout(timer);
      const pending = this.pendingPrompts.get(promptId);
      if (pending) {
        this.pendingPrompts.delete(promptId);
        const userResponse = (output === 'Yes' || output === 'OK') ? 'ok' : 'cancel';
        pending.resolve(userResponse);

        // Notify server of the response
        if (this.ws && this.ws.readyState === 1) {
          this.ws.send(JSON.stringify({
            type: 'user-prompt-response',
            prompt_id: promptId,
            response: userResponse,
            device_id: this.deviceInfo.device_id,
            timestamp: new Date().toISOString()
          }));
        }
      }
    }
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

    let response: string;

    if (this.hasAnyGuiClient()) {
      // GUI is connected — use IPC/WebSocket prompt
      response = await new Promise<string>((resolve) => {
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

        this.broadcastToAllClients({
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
    } else {
      // No GUI connected — fall back to native Windows dialog
      this.logger.info('No GUI connected, using native Windows prompt for reboot confirmation');
      const { spawnSync } = require('child_process');
      const psScript = `Add-Type -AssemblyName PresentationFramework; $result = [System.Windows.MessageBox]::Show('${message.replace(/'/g, "''")}', 'OPSIS Agent - Restart Required', 'YesNo', 'Warning'); if ($result -eq 'Yes') { Write-Output 'ok' } else { Write-Output 'cancel' }`;
      const result = spawnSync('powershell.exe', ['-NoProfile', '-Command', psScript], { timeout: 300000 });
      const output = result.stdout ? result.stdout.toString().trim() : 'timeout';
      response = output === 'ok' ? 'ok' : 'cancel';
      this.logger.info('Native reboot prompt result', { response: output });
    }

    // Get the logged-on username for authorization tracking
    const loggedOnUser = process.env.USERNAME || process.env.USER || os.userInfo().username || 'Unknown';

    if (response === 'ok') {
      this.logger.info(`User confirmed reboot, scheduling in ${delay} seconds`, { authorizedBy: loggedOnUser });

      // Notify server of reboot authorization
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({
          type: 'reboot_authorized',
          device_id: this.deviceInfo.device_id,
          tenant_id: this.deviceInfo.tenant_id,
          timestamp: new Date().toISOString(),
          authorized_by: loggedOnUser,
          playbook_id: this.playbookQueue.length > 0 ? this.playbookQueue[0]?.id : null,
          delay_seconds: delay,
          reason: rawMessage
        }));
        this.logger.info('Reboot authorization sent to server');
      }

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
      this.logger.info('User declined or timed out on reboot prompt', { response, user: loggedOnUser });

      // Notify server that reboot was declined
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({
          type: 'reboot_declined',
          device_id: this.deviceInfo.device_id,
          tenant_id: this.deviceInfo.tenant_id,
          timestamp: new Date().toISOString(),
          declined_by: loggedOnUser,
          response,
          reason: response === 'timeout' ? 'User did not respond within 5 minutes' : 'User declined reboot'
        }));
      }
    }
  }

  /**
   * Execute a user-prompt playbook step - shows message and waits for response.
   */
  private async executeUserPrompt(action: string, params: Record<string, any>): Promise<void> {
    const promptId = `step-prompt-${Date.now()}`;
    const timeout = params.timeout || 300;

    this.logger.info('User-prompt step: showing prompt to user', { action });

    let response: string;

    if (this.hasAnyGuiClient()) {
      // GUI is connected — use IPC/WebSocket prompt
      response = await new Promise<string>((resolve) => {
        const timer = setTimeout(() => {
          this.pendingPrompts.delete(promptId);
          resolve('timeout');
        }, timeout * 1000);

        this.pendingPrompts.set(promptId, {
          resolve,
          action_on_confirm: params.action_on_confirm,
          timer
        });

        this.broadcastToAllClients({
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
    } else {
      // No GUI connected — fall back to native Windows dialog
      this.logger.info('No GUI connected, using native Windows prompt for playbook user-prompt');
      const { spawnSync } = require('child_process');
      const title = String(params.title || 'Action Required').replace(/'/g, "''").replace(/[`$&|;<>\r\n"]/g, '');
      const msg = String(action).replace(/'/g, "''").replace(/[`$&|;<>\r\n"]/g, '');
      const buttons = params.buttons || ['OK', 'Cancel'];
      const hasCancel = buttons.some((b: string) => /cancel|no|later|decline/i.test(b));
      const wpfButtons = hasCancel ? 'YesNo' : 'OK';
      const psScript = `Add-Type -AssemblyName PresentationFramework; $result = [System.Windows.MessageBox]::Show('${msg}', 'OPSIS Agent - ${title}', '${wpfButtons}', 'Information'); Write-Output $result`;
      const result = spawnSync('powershell.exe', ['-NoProfile', '-Command', psScript], { timeout: timeout * 1000 });
      const output = result.stdout ? result.stdout.toString().trim() : 'timeout';
      response = (output === 'Yes' || output === 'OK') ? 'ok' : (output === 'timeout' ? 'timeout' : 'cancel');
      this.logger.info('Native user-prompt result', { promptId, result: output });
    }

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
      server_message: serverMessage,
      diagnostic_summary: `Signal: ${signatureId}\nServer message: ${serverMessage || 'Creating ticket for review'}`,
      recommended_action: runbook ? `Awaiting technician approval to run "${runbook.name}"` : 'Awaiting technician review',
      resolution_category: 'pending'
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
    this.broadcastToAllClients({
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
      this.logger.error('Diagnostic request validation failed: ' + validation.errors.join(', '), {
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
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({
          type: 'ignore_list_result',
          success: false,
          error: 'Missing signature field',
          timestamp: new Date().toISOString()
        }));
      }
      return;
    }

    this.addToLocalIgnoreList(signature, reason || 'Added by server');

    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({
        type: 'ignore_list_result',
        success: true,
        signature,
        reason: reason || 'Added by server',
        timestamp: new Date().toISOString()
      }));
    }
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

  private loadExclusionsFile(): { services: string[]; processes: string[]; signatures: string[] } {
    try {
      const exclusionsPath = path.join(process.cwd(), 'config', 'exclusions.json');
      if (fs.existsSync(exclusionsPath)) {
        const data = JSON.parse(fs.readFileSync(exclusionsPath, 'utf8'));
        return {
          services: data.services || [],
          processes: data.processes || [],
          signatures: data.signatures || []
        };
      }
    } catch (error) {
      this.logger.warn('Failed to load exclusions file', { error: String(error) });
    }
    return { services: [], processes: [], signatures: [] };
  }

  private loadIgnoreListFile(): { ignored_signatures: Array<{ signature: string; reason: string; added_at: string; verified_by: string }> } {
    try {
      const ignoreListPath = path.join(process.cwd(), 'data', 'ignore-list.json');
      if (fs.existsSync(ignoreListPath)) {
        const data = JSON.parse(fs.readFileSync(ignoreListPath, 'utf8'));
        return { ignored_signatures: data.ignored_signatures || [] };
      }
    } catch (error) {
      this.logger.warn('Failed to load ignore list file', { error: String(error) });
    }
    return { ignored_signatures: [] };
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

  /**
   * Send a security alert to the server (e.g. runbook tampering detected)
   */
  private sendSecurityAlert(alertType: string, details: Record<string, any>): void {
    const alert = {
      type: 'security_alert',
      alert_type: alertType,
      timestamp: new Date().toISOString(),
      device_id: this.deviceInfo?.device_id,
      tenant_id: this.deviceInfo?.tenant_id,
      details
    };
    this.logger.error('SECURITY ALERT', alert);
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(alert));
    }
  }

  // Handle Welcome Message from Server (heartbeat already running from on('open'))
  private async handleWelcome(data: any): Promise<void> {
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

      // Update heartbeat interval if server specifies a fixed one
      const serverHeartbeatMs = this.serverConfig!.monitoring?.heartbeat_interval;
      if (serverHeartbeatMs && serverHeartbeatMs > 0) {
        // Server mandates a fixed interval — disable adaptive telemetry
        this.serverFixedHeartbeatInterval = serverHeartbeatMs;
        this.currentHeartbeatIntervalMs = serverHeartbeatMs;
        if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
        this.heartbeatTimer = setInterval(() => this.sendHeartbeat(), serverHeartbeatMs);
        this.logger.info('Adaptive telemetry disabled — server mandates fixed interval', { interval_ms: serverHeartbeatMs });
      } else {
        // No server override — enable adaptive telemetry
        this.serverFixedHeartbeatInterval = null;
        this.updateTelemetryMode();
      }

      this.logger.info('Server config applied', {
        heartbeat_interval: serverHeartbeatMs || 'adaptive',
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

    // Apply protected applications list from server (pushed on registration)
    if (data.protected_applications) {
      this.saveProtectedApplications(data.protected_applications);
    }

    // Provision HMAC secret from server (initial setup over authenticated wss:// connection)
    if (data.hmac_secret) {
      const hmacConfigured = await isHmacConfigured();
      if (!hmacConfigured) {
        try {
          await storeHmacSecret(data.hmac_secret);
          this.logger.info('HMAC secret provisioned from server welcome');
        } catch (err) {
          this.logger.error('Failed to store HMAC secret from welcome', err);
        }
      }
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

      // Apply per-resource confidence modifier
      const resourceName = this.extractResourceName(null, runbook);
      const resourceModifier = resourceName
        ? (this.remediationMemory.shouldAttemptRemediation(
            signature.signature_id, os.hostname(), runbook.runbookId, resourceName
          ).confidenceModifier)
        : 1.0;
      const effectiveConfidence = signature.confidence_local * resourceModifier;

      this.logger.info('Runbook classification', {
        runbook_id: runbook.runbookId,
        risk_class: riskClass,
        can_auto_execute: canAutoExecute,
        confidence: signature.confidence_local,
        resource_name: resourceName,
        confidence_modifier: resourceModifier,
        effective_confidence: effectiveConfidence
      });

      if (canAutoExecute && riskClass === 'A' && effectiveConfidence >= 85) {
        // Class A with high effective confidence - Auto execute locally
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

    // Adaptive telemetry: record signal time and send immediate heartbeat
    this.recordSignalForTelemetry();

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

    // Multi-signal correlation check
    this.signalCorrelator.recordSignal(signal);
    const correlation = this.signalCorrelator.checkCorrelations(signal);
    if (correlation) {
      this.handleCorrelation(correlation, signal);
    }

    // NEW: Generate signature from system signal
    const signature = this.signatureGenerator.generateFromSystemSignal(signal, this.deviceInfo);

    // Apply correlation-based confidence boost
    if (correlation?.action.confidenceBoost) {
      signature.confidence_local = correlation.action.confidenceBoost;
    } else if (correlation?.action.confidenceDelta) {
      signature.confidence_local = Math.min(100, signature.confidence_local + correlation.action.confidenceDelta);
    }

    this.logger.info('System signature generated', {
      signature_id: signature.signature_id,
      confidence: signature.confidence_local,
      severity: signature.severity,
      correlation: correlation?.ruleId || null
    });

    // Create playbook for system signal if possible
    const playbook = this.createPlaybookForSystemSignal(signal);

    // Apply per-resource confidence modifier
    const sysResourceName = this.extractResourceName(signal, playbook);
    const sysResourceModifier = sysResourceName && playbook
      ? (this.remediationMemory.shouldAttemptRemediation(
          signature.signature_id, os.hostname(), playbook.id, sysResourceName
        ).confidenceModifier)
      : 1.0;
    const sysEffectiveConfidence = signature.confidence_local * sysResourceModifier;

    if (playbook && sysEffectiveConfidence >= 85) {
      // Capability mode gate: monitor-only and limited modes cannot auto-execute
      if (this.capabilityMode === 'monitor-only' || this.capabilityMode === 'limited') {
        this.logger.info(`Capability mode '${this.capabilityMode}' — escalating instead of auto-executing`, {
          playbook_name: playbook.name,
          signature_id: signature.signature_id
        });
        this.escalateSystemIssueToServer(signature, playbook);

      } else if (this.isTargetProtectedApp(signal)) {
        // Protected application gate: always escalate, never auto-remediate
        this.logger.info('Target is a protected application — escalating instead of auto-executing', {
          playbook_name: playbook.name,
          signal_id: signal.id,
          metadata: signal.metadata
        });
        this.escalateSystemIssueToServer(signature, playbook);

      } else {
        // High confidence + full mode - execute locally
        const diagSummary = `${signal.category} issue detected: ${signal.metric || signal.id}\nConfidence: ${signature.confidence_local}% | Severity: ${signature.severity}`;
        const recAction = `Running playbook "${playbook.name}" (${playbook.steps.length} step${playbook.steps.length !== 1 ? 's' : ''})`;
        const ticketId = this.actionTicketManager.createActionTicket(
          signature.signature_id,
          playbook.id,
          `System remediation: ${playbook.name}`,
          playbook.steps.length,
          diagSummary,
          recAction
        );

        this.activeTickets.set(playbook.id, ticketId);
        this.actionTicketManager.markInProgress(ticketId, playbook.id);
        this.receivePlaybook(playbook, 'local');
      }

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
    // Capability mode gate
    if (this.capabilityMode === 'monitor-only' || this.capabilityMode === 'limited') {
      this.logger.info(`Capability mode '${this.capabilityMode}' — escalating Class A to server`, {
        signature_id: signature.signature_id,
        runbook_id: runbook.runbookId
      });
      this.escalateToServer(signature, runbook);
      return;
    }

    this.logger.info('Executing local Class A remediation', {
      signature_id: signature.signature_id,
      runbook_id: runbook.runbookId,
      confidence: signature.confidence_local
    });

    // Create action ticket with signature_id stored
    const diagSummary = `Signature ${signature.signature_id} detected\nConfidence: ${signature.confidence_local}% | Severity: ${signature.severity}\nClass A remediation triggered`;
    const recAction = `Running playbook "${runbook.name}" (${runbook.steps.length} step${runbook.steps.length !== 1 ? 's' : ''})`;
    const ticketId = this.actionTicketManager.createActionTicket(
      signature.signature_id,
      runbook.runbookId,
      `Auto-remediation: ${runbook.name}`,
      runbook.steps.length,
      diagSummary,
      recAction
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
      fallback_chains: runbook.fallback_chains,
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

    // Check for cached server runbook before escalating
    const cachedServerRunbook = await this.findCachedServerRunbook(signature.signature_id);
    if (cachedServerRunbook) {
      this.logger.info('Using cached server runbook instead of re-escalating', {
        signature_id: signature.signature_id,
        runbook_id: cachedServerRunbook.id,
        name: cachedServerRunbook.name,
        previous_successes: cachedServerRunbook.success_count
      });

      // Build a PlaybookTask from the cached runbook and execute locally
      const cachedPlaybook: PlaybookTask = {
        id: cachedServerRunbook.original_id || cachedServerRunbook.id,
        name: cachedServerRunbook.name,
        priority: cachedServerRunbook.priority || 'medium',
        source: 'server',
        steps: cachedServerRunbook.steps,
        fallback_chains: cachedServerRunbook.fallback_chains,
        createdAt: new Date()
      };
      (cachedPlaybook as any).signalId = cachedServerRunbook.signal_id;

      // Store signature so saveServerRunbook can update execution counts
      this.pendingEscalations.set(signature.signature_id, signature);

      const ticketId = this.actionTicketManager.createActionTicket(
        signature.signature_id,
        cachedPlaybook.id,
        `Cached server remediation: ${cachedPlaybook.name}`,
        cachedPlaybook.steps.length
      );
      this.activeTickets.set(cachedPlaybook.id, ticketId);
      this.actionTicketManager.markInProgress(ticketId, cachedPlaybook.id);
      this.receivePlaybook(cachedPlaybook, 'server');
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

    // Track recent signature_id for linking server playbook responses back
    this.recentSignatureIds.unshift(signature.signature_id);
    if (this.recentSignatureIds.length > 10) {
      this.recentSignatureIds = this.recentSignatureIds.slice(0, 10);
    }

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

    // Attach baseline comparison if available
    const symptomDetails = signature.symptoms[0]?.details || {};
    const baselineDiff = this.baselineManager.getBaselineDiff({
      cpu: symptomDetails.metric === 'cpu_usage' ? symptomDetails.value : undefined,
      memory: symptomDetails.metric === 'memory_usage' ? symptomDetails.value : undefined
    });
    if (baselineDiff) {
      (escalationPayload as any).baseline_comparison = baselineDiff;
    }

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

  /**
   * Handle a multi-signal correlation result.
   * Logs the correlation and enriches escalation notes if applicable.
   */
  private handleCorrelation(correlation: CorrelationResult, triggerSignal: SystemSignal): void {
    this.logger.info('Handling signal correlation', {
      rule_id: correlation.ruleId,
      action_type: correlation.action.type,
      matched_signals: correlation.matchedSignals
    });

    // For escalation enrichment, store the note for later use in escalateToServer
    if (correlation.action.type === 'enrich_escalation' && correlation.action.escalationNote) {
      (triggerSignal as any)._correlationNote = correlation.action.escalationNote;
    }
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
    
    const symptoms = signature.symptoms.map(s => `${s.type}: ${s.severity}`).join(', ');
    const targets = signature.targets.map(t => t.name).join(', ');

    const ticket: Ticket = {
      ticket_id: ticketId,
      timestamp: new Date().toISOString(),
      type: 'manual-review',
      description: description,
      status: 'open',
      source: 'monitoring',
      computer_name: os.hostname(),
      escalated: 1,
      diagnostic_summary: `Detected symptoms: ${symptoms}\nAffected targets: ${targets}\nConfidence: ${signature.confidence_local}%`,
      recommended_action: 'Manual review required — no automated remediation available',
      resolution_category: 'escalated'
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
      escalated: 1,
      diagnostic_summary: `Event ID ${event.id} from ${event.source}\n${event.message}`,
      recommended_action: `Escalated to server — ${reason}`,
      resolution_category: 'escalated'
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
    this.escalateToServer(signature, null).catch(err => {
      this.logger.error('escalateToServer failed', err);
    });
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
    // NOTE: HMAC signature verification is now done BEFORE this method is called
    // (in the 'playbook' case handler) to avoid mutation before verification.
    if (source === 'server') {

      // Step 2: Validate playbook structure and step types
      const validation = validatePlaybook(playbook);
      if (!validation.valid) {
        this.logger.error('Playbook validation failed: ' + validation.errors.join(', '), {
          playbookId: playbook.id
        });
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
          this.ws.send(JSON.stringify({
            type: 'playbook_error',
            playbook_id: playbook.id,
            error: 'Validation failed: ' + validation.errors.join(', '),
            timestamp: new Date().toISOString()
          }));
        }
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
      const playbookResourceName = this.extractResourceName(null, playbook);

      try {
        await this.executePlaybook(playbook);
        const duration = Date.now() - startTime;

        this.log(`Playbook completed: ${playbook.name}`);
        this.reportPlaybookResult(playbook.id, 'success');
        this.sendPlaybookResult(playbook, 'success', duration);

        // Refresh software inventory after successful playbook (may have installed/removed software)
        setTimeout(() => this.sendSoftwareInventory(), 5000);

        this.remediationMemory.recordAttempt(
          playbook.id,
          signalId,
          deviceId,
          'success',
          duration,
          undefined,
          playbookResourceName
        );

        // Save successful server runbooks for future local use
        if (playbook.source === 'server') {
          await this.saveServerRunbook(playbook);
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
          error?.toString(),
          playbookResourceName
        );
      }
    }

    this.isExecutingPlaybook = false;
  }

  private async executePlaybook(playbook: PlaybookTask, resumeFromStep: number = 0): Promise<void> {
    for (let i = resumeFromStep; i < playbook.steps.length; i++) {
      const step = playbook.steps[i];
      this.log(`  Executing step ${i + 1}/${playbook.steps.length}: ${step.type} - ${step.action}`);

      if (step.requiresApproval && !this.config.autoRemediation) {
        this.log('  Step requires approval, skipping (auto-remediation disabled)');
        continue;
      }

      // If this is a reboot step and there are steps after it, save state before rebooting
      if (step.type === 'reboot' && i < playbook.steps.length - 1) {
        await this.executeStep(step);
        // If reboot was confirmed (shutdown is pending), save remaining steps for resume
        this.saveRebootPlaybookState(playbook, i + 1);
        this.logger.info('Playbook state saved for post-reboot resume', {
          playbook_id: playbook.id,
          resume_step: i + 1,
          remaining_steps: playbook.steps.length - (i + 1)
        });
        return; // Stop execution — machine is about to reboot
      }

      const isVerification = step.allowFailure || this.isVerificationStep(step, playbook.steps, i);

      try {
        await this.executeStep(step);
      } catch (error) {
        if (isVerification) {
          this.log(`  Verification step result (non-fatal): ${step.action}`, error);
          continue;
        }

        // Try fallback chain before giving up
        const fallback = this.findFallbackChain(playbook.fallback_chains, i, step, error);
        if (fallback) {
          this.log(`  Step failed, attempting fallback chain (max ${fallback.max_attempts || 1} attempts)`);
          const fallbackOk = await this.executeFallbackChain(fallback);
          if (fallbackOk) {
            this.log(`  Fallback chain succeeded, continuing to next step`);
            continue; // Fallback recovered — continue to next primary step
          }
          this.log(`  Fallback chain also failed for step: ${step.action}`);
          throw new Error(`Step "${step.action}" failed and fallback chain exhausted: ${error}`);
        }

        this.log(`  Step failed: ${step.action}`, error);
        throw error;
      }
    }

    // Playbook fully completed — clean up any reboot state file
    this.clearRebootPlaybookState();
  }

  private isVerificationStep(step: PlaybookStep, allSteps: PlaybookStep[], index: number): boolean {
    return isVerificationStep(step, allSteps, index);
  }

  private findFallbackChain(
    chains: FallbackChain[] | undefined,
    stepIndex: number,
    step: PlaybookStep,
    error: any
  ): FallbackChain | null {
    if (!chains || chains.length === 0) return null;

    const errorStr = String(error).toLowerCase();

    for (const chain of chains) {
      if (chain.trigger !== 'step_failure') continue;

      const cond = chain.condition;
      if (!cond) return chain; // No condition = matches any failure

      if (cond.failed_step_index !== undefined && cond.failed_step_index !== stepIndex) continue;
      if (cond.failed_step_type && cond.failed_step_type !== step.type) continue;
      if (cond.error_pattern && !errorStr.includes(cond.error_pattern.toLowerCase())) continue;

      return chain;
    }

    return null;
  }

  private async executeFallbackChain(chain: FallbackChain): Promise<boolean> {
    const maxAttempts = chain.max_attempts || 1;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      this.log(`  Fallback attempt ${attempt}/${maxAttempts}`);
      let allStepsOk = true;

      for (let j = 0; j < chain.fallback_steps.length; j++) {
        const fbStep = chain.fallback_steps[j];
        this.log(`    Fallback step ${j + 1}/${chain.fallback_steps.length}: ${fbStep.type} - ${fbStep.action}`);
        try {
          await this.executeStep(fbStep);
        } catch (fbError) {
          if (fbStep.allowFailure) {
            this.log(`    Fallback step failed (non-fatal): ${fbStep.action}`, fbError);
            continue;
          }
          this.log(`    Fallback step failed: ${fbStep.action}`, fbError);
          allStepsOk = false;
          break;
        }
      }

      if (allStepsOk) return true;
    }

    return false;
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

    let stdout: string;
    let stderr: string;

    // Multi-line scripts: write to temp .ps1 file and execute with -File
    // Uses {app}/data/temp/ under the agent install directory (owned by SYSTEM + Admins)
    if (effectiveScript.includes('\n') || effectiveScript.includes('"')) {
      const tempDir = path.join(this.dataDir, 'temp');
      if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });
      const tempFile = path.join(tempDir, `pb-${Date.now()}.ps1`);
      try {
        fs.writeFileSync(tempFile, effectiveScript, 'utf8');
        const result = await execAsync(
          `powershell -NoProfile -ExecutionPolicy Bypass -File "${tempFile}"`,
          { timeout }
        );
        stdout = result.stdout;
        stderr = result.stderr;
      } finally {
        try { fs.unlinkSync(tempFile); } catch {}
      }
    } else {
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
      const result = await execAsync(command, { timeout });
      stdout = result.stdout;
      stderr = result.stderr;
    }
    
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

    // Block actions on protected services (OS-critical)
    if (isProtectedService(serviceName) && (action === 'stop' || action === 'restart')) {
      this.logger.error('Blocked action on protected service', { serviceName, action });
      throw new Error(`Cannot ${action} protected service: ${serviceName}`);
    }

    // Block actions on client-protected applications
    if (this.isProtectedAppByName(serviceName) && (action === 'stop' || action === 'restart')) {
      this.logger.error('Blocked action on client-protected application', { serviceName, action });
      throw new Error(`Cannot ${action} client-protected application: ${serviceName} — requires manual approval`);
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
            'success',
            'fixed'
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

          // Check if this is a safety validation block
          const errorStr = error?.toString() || '';
          const isProtected = errorStr.includes('Safety validation') || errorStr.includes('protected service');

          // Still mark ticket as failed locally
          this.ticketDb.updateTicketStatus(ticketId, 'failed');
          this.ticketDb.closeTicket(
            ticketId,
            `Playbook failed: ${errorStr || 'Unknown error'}`,
            'failure',
            isProtected ? 'protected' : 'escalated'
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

    this.broadcastToAllClients({ type: 'maintenance-window-added', data: window });
  }

  private handleCancelMaintenanceWindow(data: any): void {
    const windowId = data.id || data.window_id;
    if (windowId) {
      this.maintenanceManager.removeWindow(windowId);
      this.broadcastToAllClients({ type: 'maintenance-window-removed', data: { id: windowId } });
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

  private async collectSystemInfo(): Promise<Record<string, any>> {
    const cpus = os.cpus();
    const totalMemGb = Math.round(os.totalmem() / 1024 / 1024 / 1024);

    let cpuModel = cpus.length > 0 ? cpus[0].model : 'Unknown';
    let cpuCores = cpus.length;
    let totalDiskGb = 0;
    let ipAddress = '';
    let macAddress = '';
    let osVersion = `${os.platform()} ${os.release()}`;

    try {
      // Get disk size, IP, MAC, and OS version via PowerShell in one call
      const { stdout } = await execAsync(
        `powershell -NoProfile -Command "$disk = Get-PSDrive -Name C -PSProvider FileSystem; $net = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1; $ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {$_.IPAddress -ne '127.0.0.1' -and $_.PrefixOrigin -ne 'WellKnown'} | Select-Object -First 1).IPAddress; $osInfo = (Get-CimInstance Win32_OperatingSystem).Caption; [PSCustomObject]@{ DiskGB=[math]::Round(($disk.Used + $disk.Free) / 1GB); IP=$ip; MAC=$net.MacAddress; OSVer=$osInfo } | ConvertTo-Json -Compress"`,
        { timeout: 15000 }
      );
      const info = JSON.parse(stdout || '{}');
      totalDiskGb = info.DiskGB || 0;
      ipAddress = info.IP || '';
      macAddress = (info.MAC || '').replace(/-/g, ':');
      if (info.OSVer) osVersion = info.OSVer;
    } catch (error) {
      this.logger.error('Failed to collect system info for registration', error);
    }

    return {
      cpuModel,
      cpuCores,
      totalMemoryGb: totalMemGb,
      totalDiskGb,
      ipAddress,
      macAddress,
      osType: 'Windows',
      osVersion,
      agentVersion: '1.0.0'
    };
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
  // PROTECTED APPLICATIONS
  // ============================================

  /**
   * Check if a signal targets a protected application.
   * Protected apps are never auto-remediated — always escalated with diagnostics.
   */
  private isTargetProtectedApp(signal: SystemSignal): boolean {
    if (this.protectedApplications.length === 0) return false;

    const serviceName = signal.metadata?.serviceName?.toLowerCase();
    const processName = signal.metadata?.processName?.toLowerCase();

    return this.protectedApplications.some(app => {
      if (app.service_name && serviceName && app.service_name.toLowerCase() === serviceName) return true;
      if (app.process_name && processName && app.process_name.toLowerCase() === processName) return true;
      return false;
    });
  }

  /**
   * Check if a process or service name is in the protected applications list.
   */
  private isProtectedAppByName(name: string): boolean {
    if (!name || this.protectedApplications.length === 0) return false;
    const lower = name.toLowerCase();
    return this.protectedApplications.some(app =>
      (app.service_name && app.service_name.toLowerCase() === lower) ||
      (app.process_name && app.process_name.toLowerCase() === lower)
    );
  }

  /**
   * Extract a resource name from a signal or runbook for per-resource confidence tracking.
   * Returns e.g. "Spooler" for a service-stopped signal, "chrome.exe" for a process signal.
   */
  private extractResourceName(signal?: SystemSignal | null, runbook?: any): string | undefined {
    if (signal?.metadata?.serviceName) return signal.metadata.serviceName;
    if (signal?.metadata?.processName) return signal.metadata.processName;
    if (signal?.metadata?.drive) return signal.metadata.drive;
    // Check runbook step params for a serviceName
    if (runbook?.steps) {
      for (const step of runbook.steps) {
        if (step.params?.serviceName && !step.params.serviceName.includes('{')) {
          return step.params.serviceName;
        }
      }
    }
    return undefined;
  }

  /**
   * Load protected applications from local config file.
   * These are synced from the server via config-update messages.
   */
  private loadProtectedApplications(): void {
    try {
      const protectedPath = path.join(this.baseDir, 'config', 'protected-applications.json');
      if (fs.existsSync(protectedPath)) {
        const data = JSON.parse(fs.readFileSync(protectedPath, 'utf8'));
        this.protectedApplications = data.applications || [];
        this.logger.info('Loaded protected applications', { count: this.protectedApplications.length });
      }
    } catch (error) {
      this.logger.warn('Failed to load protected applications', { error: String(error) });
    }
  }

  /**
   * Save protected applications to local config and merge into exclusions.
   */
  private saveProtectedApplications(applications: Array<{ process_name?: string; service_name?: string; display_name: string }>): void {
    this.protectedApplications = applications;

    try {
      const configDir = path.join(this.baseDir, 'config');
      if (!fs.existsSync(configDir)) {
        fs.mkdirSync(configDir, { recursive: true });
      }
      fs.writeFileSync(
        path.join(configDir, 'protected-applications.json'),
        JSON.stringify({ applications, updated_at: new Date().toISOString() }, null, 2),
        'utf8'
      );

      // Also merge into exclusions.json for backward compatibility
      for (const app of applications) {
        if (app.service_name) this.addToExclusionList(app.service_name, 'services');
        if (app.process_name) this.addToExclusionList(app.process_name, 'processes');
      }

      this.logger.info('Protected applications saved', { count: applications.length });
    } catch (error) {
      this.logger.error('Failed to save protected applications', error);
    }
  }

  // ============================================
  // REBOOT PLAYBOOK STATE PERSISTENCE
  // ============================================

  /**
   * Save playbook state before a reboot so it can resume after restart.
   */
  private saveRebootPlaybookState(playbook: PlaybookTask, resumeFromStep: number): void {
    try {
      const loggedOnUser = process.env.USERNAME || process.env.USER || os.userInfo().username || 'Unknown';
      const state = {
        playbook: {
          id: playbook.id,
          name: playbook.name,
          priority: playbook.priority,
          source: playbook.source,
          steps: playbook.steps,
          fallback_chains: playbook.fallback_chains,
          signalId: (playbook as any).signalId,
          signatureId: (playbook as any).signatureId
        },
        resumeFromStep,
        savedAt: new Date().toISOString(),
        authorizedBy: loggedOnUser,
        deviceId: os.hostname()
      };
      fs.writeFileSync(this.pendingRebootPlaybookPath, JSON.stringify(state, null, 2), 'utf8');
    } catch (error) {
      this.logger.error('Failed to save reboot playbook state', error);
    }
  }

  /**
   * Check for and resume a playbook that was interrupted by a reboot.
   * Sends reboot_completed to server once WebSocket connects.
   */
  private async resumeRebootPlaybook(): Promise<void> {
    try {
      if (!fs.existsSync(this.pendingRebootPlaybookPath)) return;

      const raw = fs.readFileSync(this.pendingRebootPlaybookPath, 'utf8');
      const state = JSON.parse(raw);

      // Validate state
      if (!state.playbook || !state.playbook.steps || typeof state.resumeFromStep !== 'number') {
        this.logger.warn('Invalid reboot playbook state file, removing');
        this.clearRebootPlaybookState();
        return;
      }

      // Check age — don't resume if saved more than 1 hour ago
      const savedAt = new Date(state.savedAt).getTime();
      if (Date.now() - savedAt > 60 * 60 * 1000) {
        this.logger.warn('Reboot playbook state is too old (>1 hour), discarding', {
          savedAt: state.savedAt,
          playbookId: state.playbook.id
        });
        this.clearRebootPlaybookState();
        return;
      }

      this.logger.info('Resuming playbook after reboot', {
        playbook_id: state.playbook.id,
        playbook_name: state.playbook.name,
        resume_step: state.resumeFromStep,
        total_steps: state.playbook.steps.length,
        authorized_by: state.authorizedBy,
        saved_at: state.savedAt
      });

      // Queue reboot_completed notification to send once WebSocket connects
      const rebootCompletedMsg = {
        type: 'reboot_completed',
        device_id: this.deviceInfo.device_id,
        tenant_id: this.deviceInfo.tenant_id,
        timestamp: new Date().toISOString(),
        reboot_requested_at: state.savedAt,
        authorized_by: state.authorizedBy || 'Unknown',
        playbook_id: state.playbook.id,
        playbook_name: state.playbook.name,
        resume_step: state.resumeFromStep,
        total_steps: state.playbook.steps.length,
        downtime_seconds: Math.round((Date.now() - savedAt) / 1000)
      };
      this.pendingRebootCompletedMsg = rebootCompletedMsg;

      // Rebuild PlaybookTask
      const playbook: PlaybookTask = {
        id: state.playbook.id,
        name: state.playbook.name,
        priority: state.playbook.priority || 'medium',
        source: state.playbook.source || 'server',
        steps: state.playbook.steps,
        fallback_chains: state.playbook.fallback_chains,
        createdAt: new Date()
      };
      if (state.playbook.signalId) (playbook as any).signalId = state.playbook.signalId;
      if (state.playbook.signatureId) (playbook as any).signatureId = state.playbook.signatureId;

      // Validate that the original issue still exists before resuming
      const issueStillPresent = await this.isOriginalIssueStillPresent(state);
      if (!issueStillPresent) {
        this.logger.info('Original issue resolved after reboot, skipping playbook resume', {
          playbook_id: playbook.id,
          playbook_name: playbook.name,
          signal_id: state.playbook.signalId
        });
        this.reportPlaybookResult(playbook.id, 'success');
        this.sendPlaybookResult(playbook, 'success', 0);
        const signalId = (playbook as any).signalId || playbook.id;
        const rebootResourceName = this.extractResourceName(null, playbook);
        this.remediationMemory.recordAttempt(playbook.id, signalId, os.hostname(), 'success', 0, undefined, rebootResourceName);
        this.clearRebootPlaybookState();
        return;
      }

      // Execute remaining steps
      const startTime = Date.now();
      const signalId = (playbook as any).signalId || playbook.id;
      const deviceId = os.hostname();
      const rebootResourceName = this.extractResourceName(null, playbook);

      try {
        await this.executePlaybook(playbook, state.resumeFromStep);
        const duration = Date.now() - startTime;

        this.logger.info('Post-reboot playbook completed', {
          playbook_id: playbook.id,
          duration_ms: duration
        });
        this.reportPlaybookResult(playbook.id, 'success');
        this.sendPlaybookResult(playbook, 'success', duration);

        this.remediationMemory.recordAttempt(playbook.id, signalId, deviceId, 'success', duration, undefined, rebootResourceName);

        if (playbook.source === 'server') {
          await this.saveServerRunbook(playbook);
        }
      } catch (error) {
        const duration = Date.now() - startTime;

        this.logger.error('Post-reboot playbook failed', { playbook_id: playbook.id, error });
        this.reportPlaybookResult(playbook.id, 'failed', error);
        this.sendPlaybookResult(playbook, 'failed', duration, error);

        this.remediationMemory.recordAttempt(playbook.id, signalId, deviceId, 'failure', duration, error?.toString(), rebootResourceName);
      }

      // Always clean up state file after attempting resume
      this.clearRebootPlaybookState();
    } catch (error) {
      this.logger.error('Failed to resume reboot playbook', error);
      this.clearRebootPlaybookState();
    }
  }

  /**
   * Delete the reboot playbook state file.
   */
  private clearRebootPlaybookState(): void {
    try {
      if (fs.existsSync(this.pendingRebootPlaybookPath)) {
        fs.unlinkSync(this.pendingRebootPlaybookPath);
      }
    } catch (error) {
      this.logger.error('Failed to clear reboot playbook state', error);
    }
  }

  /**
   * Check whether the original issue that triggered a playbook still exists after reboot.
   * Returns true if the issue is still present (or if we can't determine), false if resolved.
   * Fail-open: on any error or timeout, returns true to allow resume.
   */
  private async isOriginalIssueStillPresent(state: any): Promise<boolean> {
    const signalId: string = state.playbook.signalId || '';
    const playbookName: string = state.playbook.name || '';

    // Playbooks that should always resume (verification/cleanup after reboot)
    const alwaysResumePatterns = ['reboot-verification', 'disk-cleanup', 'diagnostic', 'verify'];
    if (alwaysResumePatterns.some(p => playbookName.toLowerCase().includes(p))) {
      return true;
    }

    try {
      // Service signals — check if the service is still stopped
      if (signalId.includes('service') || playbookName.toLowerCase().includes('service')) {
        const serviceName = state.playbook.steps?.[0]?.parameters?.serviceName
          || state.playbook.signalId?.replace(/^service[-_]stopped[-_]/i, '');
        if (serviceName) {
          const { stdout } = await execAsync(
            `powershell -Command "(Get-Service -Name '${serviceName.replace(/'/g, "''")}' -ErrorAction SilentlyContinue).Status"`,
            { timeout: 10000 }
          );
          const status = stdout.trim().toLowerCase();
          if (status === 'running') {
            this.logger.info('Service is already running after reboot, issue resolved', { serviceName, status });
            return false;
          }
        }
      }

      // CPU signals — check if CPU is still breaching
      if (signalId.includes('cpu') || playbookName.toLowerCase().includes('cpu')) {
        const { stdout } = await execAsync(
          'powershell -Command "(Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average"',
          { timeout: 10000 }
        );
        const cpuUsage = parseFloat(stdout.trim());
        if (!isNaN(cpuUsage) && cpuUsage < 75) {
          this.logger.info('CPU usage normal after reboot, issue resolved', { cpuUsage });
          return false;
        }
      }

      // Memory signals — check if memory is still breaching
      if (signalId.includes('memory') || playbookName.toLowerCase().includes('memory')) {
        const { stdout } = await execAsync(
          'powershell -Command "$os = Get-CimInstance Win32_OperatingSystem; [math]::Round(($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize * 100, 1)"',
          { timeout: 10000 }
        );
        const memUsage = parseFloat(stdout.trim());
        if (!isNaN(memUsage) && memUsage < 80) {
          this.logger.info('Memory usage normal after reboot, issue resolved', { memUsage });
          return false;
        }
      }

      // Network signals — check basic connectivity
      if (signalId.includes('network') || signalId.includes('dns') || playbookName.toLowerCase().includes('network')) {
        const { stdout } = await execAsync(
          'powershell -Command "Test-Connection -ComputerName 8.8.8.8 -Count 1 -Quiet"',
          { timeout: 10000 }
        );
        if (stdout.trim().toLowerCase() === 'true') {
          this.logger.info('Network connectivity restored after reboot, issue resolved');
          return false;
        }
      }

      // Disk signals — check if free space is still low
      if (signalId.includes('disk') && !signalId.includes('health')) {
        const { stdout } = await execAsync(
          'powershell -Command "$d = Get-PSDrive C; [math]::Round($d.Free / ($d.Used + $d.Free) * 100, 1)"',
          { timeout: 10000 }
        );
        const freePercent = parseFloat(stdout.trim());
        if (!isNaN(freePercent) && freePercent > 20) {
          this.logger.info('Disk space adequate after reboot, issue resolved', { freePercent });
          return false;
        }
      }

    } catch (error) {
      // Fail-open: if we can't check, assume issue still exists and resume
      this.logger.warn('Pre-resume validation failed, proceeding with resume', { error: String(error) });
      return true;
    }

    // Default: assume issue still exists
    return true;
  }

  // ============================================
  // SERVER RUNBOOK STORAGE & REINVESTIGATION
  // ============================================

  /**
   * Save a successful server runbook for future local use
   */
  private async saveServerRunbook(playbook: PlaybookTask): Promise<void> {
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

      // Find the signature_id that triggered this playbook (for future cache matching)
      const signalId = (playbook as any).signalId || playbook.id;
      // Use the most recent escalation signature, or check pending escalations
      let matchedSignatureId: string | null = (playbook as any).signatureId || null;
      if (!matchedSignatureId && this.recentSignatureIds.length > 0) {
        matchedSignatureId = this.recentSignatureIds[0];
      }
      if (!matchedSignatureId) {
        for (const [sigId] of this.pendingEscalations.entries()) {
          matchedSignatureId = sigId;
          break;
        }
      }

      const runbookEntry: Record<string, any> = {
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
        signal_id: signalId,
        signature_id: matchedSignatureId,
        triggers: (playbook as any).triggers || []
      };
      if (playbook.fallback_chains) {
        runbookEntry.fallback_chains = playbook.fallback_chains;
      }

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

      // Register integrity hash BEFORE writing to disk
      try {
        const canonicalContent = canonicalizeServerRunbook(runbookEntry);
        await registerRunbookHash('server:' + runbookEntry.id, canonicalContent);
      } catch (hashError) {
        this.logger.warn('Failed to register runbook integrity hash (continuing)', hashError);
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
   * Find a cached server runbook by signature_id for local reuse.
   * Returns the runbook with the highest success count for this signature.
   */
  private async findCachedServerRunbook(signatureId: string): Promise<any | null> {
    try {
      if (!fs.existsSync(this.serverRunbooksPath)) return null;

      const findBestMatch = (): any | null => {
        const serverRunbooks = JSON.parse(fs.readFileSync(this.serverRunbooksPath, 'utf8'));
        const matching = serverRunbooks.runbooks.filter(
          (rb: any) => rb.signature_id === signatureId && !rb.resolved && rb.success_count > 0 && rb.steps && rb.steps.length > 0
        );
        if (matching.length === 0) return null;
        return matching.sort((a: any, b: any) => b.success_count - a.success_count)[0];
      };

      const best = findBestMatch();
      if (!best) return null;

      // Verify integrity before trusting cached runbook
      const canonicalContent = canonicalizeServerRunbook(best);
      const integrity = await verifyRunbookIntegrity('server:' + best.id, canonicalContent);

      if (integrity.reason === 'hash_mismatch') {
        // Race condition guard: saveServerRunbook() may have updated the hash
        // while we were reading. Re-read the file and verify once more.
        this.logger.warn('Runbook hash mismatch on first check, retrying (possible race condition)', {
          runbook_id: best.id,
          signature_id: signatureId,
        });

        const retryBest = findBestMatch();
        if (!retryBest) return null;

        const retryCanonical = canonicalizeServerRunbook(retryBest);
        const retryIntegrity = await verifyRunbookIntegrity('server:' + retryBest.id, retryCanonical);

        if (retryIntegrity.reason === 'hash_mismatch') {
          // Still mismatches after retry — genuine tampering
          this.logger.error('SECURITY: Cached server runbook tampered — refusing execution', {
            runbook_id: retryBest.id,
            signature_id: signatureId,
            expected_hash: retryIntegrity.expected_hash,
            actual_hash: retryIntegrity.actual_hash,
          });
          this.sendSecurityAlert('runbook_tampering', {
            runbook_id: retryBest.id,
            file_path: this.serverRunbooksPath,
            signature_id: signatureId,
            expected_hash: retryIntegrity.expected_hash,
            actual_hash: retryIntegrity.actual_hash,
          });
          return null;
        }

        // Retry passed — was a race condition, not tampering
        this.logger.info('Runbook hash verified on retry (was race condition)', {
          runbook_id: retryBest.id,
        });
        return retryBest;
      }

      if (integrity.reason === 'no_stored_hash') {
        // Migration: first load after upgrade — register hash and proceed
        try {
          await registerRunbookHash('server:' + best.id, canonicalContent);
        } catch (hashError) {
          this.logger.warn('Failed to register runbook hash during migration', hashError);
        }
      }

      this.logger.info('Found cached server runbook for signature', {
        signatureId,
        runbookId: best.id,
        name: best.name,
        success_count: best.success_count,
        execution_count: best.execution_count,
        integrity: integrity.reason,
      });
      return best;
    } catch (error) {
      this.logger.error('Failed to find cached server runbook', error);
      return null;
    }
  }

  // Report self-service resolution to server for MSP dashboard metrics
  private reportSelfServiceResolution(data: {
    category: string;
    resolution_time_seconds: number;
    user_satisfaction?: number;
    fix_applied?: string;
    auto_resolved: boolean;
    session_messages: number;
    ticket_id?: string;
  }): void {
    this.logger.info('Self-service resolution', data);

    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({
        type: 'self_service_resolution',
        timestamp: new Date().toISOString(),
        device_id: this.deviceInfo.device_id,
        tenant_id: this.deviceInfo.tenant_id,
        data
      }));
    }
  }
}

// ============================================
// SERVICE ENTRY POINT
// ============================================

// Prevent multiple instances via PID lock file
const lockFilePath = path.join(process.cwd(), 'data', 'agent.pid');

function acquireLock(): boolean {
  try {
    if (fs.existsSync(lockFilePath)) {
      const existingPid = parseInt(fs.readFileSync(lockFilePath, 'utf8').trim(), 10);
      if (!isNaN(existingPid)) {
        try {
          // Check if process is still running (signal 0 doesn't kill, just checks)
          process.kill(existingPid, 0);
          // Process exists — another instance is running
          console.error(`OPSIS Agent already running (PID ${existingPid}). Exiting.`);
          return false;
        } catch {
          // Process not found — stale lock file, safe to overwrite
        }
      }
    }
    // Ensure data directory exists
    const dataDir = path.join(process.cwd(), 'data');
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }
    fs.writeFileSync(lockFilePath, String(process.pid));
    return true;
  } catch (err) {
    console.error('Failed to acquire lock:', err);
    return false;
  }
}

function releaseLock(): void {
  try {
    if (fs.existsSync(lockFilePath)) {
      const pid = parseInt(fs.readFileSync(lockFilePath, 'utf8').trim(), 10);
      if (pid === process.pid) {
        fs.unlinkSync(lockFilePath);
      }
    }
  } catch { /* best effort */ }
}

if (!acquireLock()) {
  process.exit(1);
}

const agent = new OPSISAgentService();

process.on('SIGINT', () => {
  agent.stop();
  releaseLock();
  process.exit(0);
});

process.on('SIGTERM', () => {
  agent.stop();
  releaseLock();
  process.exit(0);
});

process.on('exit', () => {
  releaseLock();
});

agent.start().catch((error) => {
  console.error('Fatal error:', error);
  releaseLock();
  process.exit(1);
});

export default OPSISAgentService;
