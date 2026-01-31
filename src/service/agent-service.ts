// agent-service.ts - Production OPSIS Agent Service with Tiered Intelligence Integration
import * as os from 'os';
import * as fs from 'fs';
import * as path from 'path';
import * as https from 'https';
import { exec } from 'child_process';
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
  type: 'powershell' | 'registry' | 'service' | 'file' | 'wmi' | 'diagnostic';
  action: string;
  params: Record<string, any>;
  timeout?: number;
  requiresApproval?: boolean;
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

  // NEW PROPERTIES - Tiered Intelligence
  private signatureGenerator: SignatureGenerator;
  private escalationProtocol: EscalationProtocol;
  private runbookClassifier: RunbookClassifier;
  private actionTicketManager: ActionTicketManager;
  private deviceInfo: DeviceInfo;
  private recentActions: Array<{ 
    playbook_id: string; 
    result: 'success' | 'failure' | 'partial'; 
    timestamp: string;
  }> = [];
  private pendingEscalations: Map<string, DeviceSignature> = new Map(); // signature_id -> signature

  // Reconnect backoff state
  private reconnectAttempts: number = 0;
  private readonly RECONNECT_BASE_MS = 1000;
  private readonly RECONNECT_MAX_MS = 5 * 60 * 1000; // 5 minutes
  private sessionValid: boolean = true;

  // Server-provided configuration (received via welcome message)
  private serverConfig: ServerConfig | null = null;
  private heartbeatTimer: NodeJS.Timeout | null = null;
  private telemetryTimer: NodeJS.Timeout | null = null;

  constructor() {
    this.dataDir = path.join(__dirname, '..', '..', 'data');
    this.logsDir = path.join(__dirname, '..', '..', 'logs');
    this.runbooksDir = path.join(__dirname, '..', '..', 'runbooks');
    this.configPath = path.join(this.dataDir, 'agent.config.json');
    
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
      fs.writeFileSync(this.configPath, JSON.stringify(this.config, null, 2));
      this.logger.info('Configuration saved');
    } catch (err) {
      this.logger.error('Error saving config', err);
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
        `powershell -Command "(Get-MpPreference).ExclusionPath -contains '${path.join(__dirname, '..', '..')}'  "`,
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

    // Check what this endpoint allows before starting operations
    await this.detectPolicyRestrictions();

    // Start IPC server for GUI
    this.ipcServer.start();
    this.log('IPC server started');

    // Start event monitoring
    this.eventMonitor.startMonitoring(30);
    this.log('Event monitoring started');

    // Start system monitoring
    this.systemMonitor.start();
    this.log('System monitoring started (60 second intervals)');

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

    this.log('OPSIS Agent Service Started Successfully');
  }

  public stop(): void {
    this.log('OPSIS Agent Service Stopping...');
    
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

    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
    }

    if (this.telemetryTimer) {
      clearInterval(this.telemetryTimer);
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
        this.log('Connected to OPSIS server, waiting for welcome...');
        this.reconnectAttempts = 0; // Reset backoff on successful connection
        // Don't start heartbeat yet — wait for welcome message with config
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
    try {
      const data = JSON.parse(message);
      
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
          this.handleDiagnosticRequest(data);
          break;

        case 'diagnostic_complete':
          this.handleDiagnosticComplete(data);
          break;

        case 'add_to_ignore_list':
          this.handleAddToIgnoreList(data);
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

        default:
          this.log(`Unknown message type: ${data.type}`);
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
  // DIAGNOSTIC REQUEST/RESPONSE (N8N Integration)
  // ============================================

  private async handleDiagnosticRequest(data: any): Promise<void> {
    const { session_id, step_id, command, timeout, description } = data;

    this.logger.info('Diagnostic request received', {
      session_id,
      step_id,
      description
    });

    try {
      const result = await this.executePowerShellCommand(command, timeout || 30);
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

  private parseDiagnosticOutput(output: string, stepId: string): any {
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

  // NEW METHOD: Handle Welcome Message from Server
  private handleWelcome(data: any): void {
    this.logger.info('Welcome received from server', {
      client_name: data.client_name,
      tenant_id: data.tenant_id,
      device_id: data.device_id,
      endpoint_id: data.endpoint_id
    });

    // Update device info with server-assigned values
    this.deviceInfo.tenant_id = data.tenant_id || this.deviceInfo.tenant_id;
    this.deviceInfo.device_id = data.device_id || this.deviceInfo.device_id;

    // Store server configuration
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

      // Start heartbeat with server-provided interval
      const heartbeatMs = this.serverConfig!.monitoring?.heartbeat_interval || 30000;
      if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
      this.sendHeartbeat();
      this.heartbeatTimer = setInterval(() => this.sendHeartbeat(), heartbeatMs);

      this.logger.info('Server config applied', {
        heartbeat_interval: heartbeatMs,
        thresholds: this.serverConfig!.thresholds,
        features: this.serverConfig!.features
      });
    } else {
      // No config — start heartbeat with default interval
      this.sendHeartbeat();
      this.heartbeatTimer = setInterval(() => this.sendHeartbeat(), 30000);
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

    // NEW: Generate signature from event
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
      // No remediation - create manual ticket
      this.createManualTicket(signature);
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

  // NEW METHOD: Escalate to Server (Tier 2) - FIXED
  private escalateToServer(signature: DeviceSignature, runbook: RunbookMatch | null): void {
    // Check ignore list before escalating
    if (this.shouldIgnoreSignature(signature.signature_id)) {
      this.logger.debug('Ignoring signal - on ignore list', {
        signal_id: signature.signature_id
      });
      return;
    }

    this.logger.info('Escalating to server (Tier 2)', {
      signature_id: signature.signature_id,
      has_runbook: !!runbook,
      confidence: signature.confidence_local
    });

    // Build escalation payload
    const escalationPayload = this.escalationProtocol.buildEscalationPayload(
      signature,
      runbook,
      this.recentActions
    );

    // Store pending escalation
    this.pendingEscalations.set(signature.signature_id, signature);

    // Send via WebSocket if connected
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      // FIXED: Spread the escalation payload at root level with type field
      this.ws.send(JSON.stringify({
        type: 'escalation',
        ...escalationPayload
      }));

      this.logger.info('Escalation sent to server', {
        signature_id: escalationPayload.signature_id,
        requested_outcome: escalationPayload.requested_outcome
      });
    } else {
      this.logger.warn('WebSocket not connected, creating manual ticket', {
        signature_id: signature.signature_id
      });
      
      // Fallback: Create manual ticket
      this.createManualTicket(signature);
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

  public receivePlaybook(playbook: PlaybookTask, source: 'server' | 'admin' | 'local'): void {
    playbook.source = source;
    playbook.createdAt = new Date();

    this.log(`Received playbook: ${playbook.name} (${source} - ${playbook.priority})`);

    // Check if this is an ignore instruction from the server
    if (source === 'server') {
      const ignoreCheck = this.isIgnoreInstruction(playbook);
      if (ignoreCheck.isIgnore) {
        this.logger.info('Playbook detected as ignore instruction', {
          playbookId: playbook.id,
          reason: ignoreCheck.reason
        });

        const signalId = (playbook as any).signalId || playbook.id;

        // Infer exclusion from signal
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
    for (const step of playbook.steps) {
      this.log(`  Executing step: ${step.type} - ${step.action}`);

      if (step.requiresApproval && !this.config.autoRemediation) {
        this.log('  Step requires approval, skipping (auto-remediation disabled)');
        continue;
      }

      try {
        await this.executeStep(step);
      } catch (error) {
        this.log(`  Step failed: ${step.action}`, error);
        throw error;
      }
    }
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
