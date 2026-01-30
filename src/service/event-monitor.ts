// event-monitor.ts - Windows Event Log Monitor with Runbook Matching
import { exec } from 'child_process';
import { promisify } from 'util';
import { Logger } from '../common/logger';
import * as fs from 'fs';
import * as path from 'path';

const execAsync = promisify(exec);

export interface EventLogEntry {
  timeCreated: Date;
  id: number;
  level: string;
  source: string;
  message: string;
  computer: string;
  logName: string;
  raw?: any;
}

export interface RunbookMatch {
  runbookId: string;
  name: string;
  confidence: number;
  trigger: string;
  steps: RunbookStep[];
}

export interface RunbookStep {
  type: 'powershell' | 'service' | 'registry' | 'file' | 'diagnostic' | 'wmi';
  action: string;
  params: Record<string, any>;
  timeout?: number;
  requiresApproval?: boolean;
}

export interface Runbook {
  id: string;
  name: string;
  description: string;
  triggers: RunbookTrigger[];
  steps: RunbookStep[];
  priority: 'critical' | 'high' | 'medium' | 'low';
  requiresApproval: boolean;
}

export interface RunbookTrigger {
  logName: string;          // System, Application, Security
  eventId?: number;         // Specific event ID
  source?: string;          // Event source
  level?: string;           // Error, Warning, Information
  messagePattern?: string;  // Regex pattern to match message
}

export class EventMonitor {
  private logger: Logger;
  private runbooks: Map<string, Runbook> = new Map();
  private runbooksPath: string;
  private isMonitoring: boolean = false;
  private monitoringInterval: NodeJS.Timeout | null = null;
  private lastCheckedTime: Date;
  private onIssueDetected: (event: EventLogEntry, runbook?: RunbookMatch) => void;
  private onEscalationNeeded: (event: EventLogEntry, reason: string) => void;

  constructor(
    logger: Logger,
    runbooksPath: string,
    onIssueDetected: (event: EventLogEntry, runbook?: RunbookMatch) => void,
    onEscalationNeeded: (event: EventLogEntry, reason: string) => void
  ) {
    this.logger = logger;
    this.runbooksPath = runbooksPath;
    // Start from beginning of today for first scan
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    this.lastCheckedTime = today;
    this.onIssueDetected = onIssueDetected;
    this.onEscalationNeeded = onEscalationNeeded;
    
    this.loadRunbooks();
  }

  // ============================================
  // RUNBOOK MANAGEMENT
  // ============================================

  private loadRunbooks(): void {
    try {
      if (!fs.existsSync(this.runbooksPath)) {
        fs.mkdirSync(this.runbooksPath, { recursive: true });
      }

      const files = fs.readdirSync(this.runbooksPath);
      const jsonFiles = files.filter(f => f.endsWith('.json'));
      
      // Create default runbooks if none exist
      if (jsonFiles.length === 0) {
        this.logger.info('No runbooks found, creating defaults...');
        this.createDefaultRunbooks();
        // Re-read files after creating defaults
        const newFiles = fs.readdirSync(this.runbooksPath);
        for (const file of newFiles) {
          if (file.endsWith('.json')) {
            const filePath = path.join(this.runbooksPath, file);
            const content = fs.readFileSync(filePath, 'utf8');
            const runbook: Runbook = JSON.parse(content);
            this.runbooks.set(runbook.id, runbook);
            this.logger.info(`Loaded runbook: ${runbook.name}`, { id: runbook.id });
          }
        }
      } else {
        // Load existing runbooks
        for (const file of jsonFiles) {
          const filePath = path.join(this.runbooksPath, file);
          const content = fs.readFileSync(filePath, 'utf8');
          const runbook: Runbook = JSON.parse(content);
          this.runbooks.set(runbook.id, runbook);
          this.logger.info(`Loaded runbook: ${runbook.name}`, { id: runbook.id });
        }
      }

      this.logger.info(`Loaded ${this.runbooks.size} runbooks`);
    } catch (error) {
      this.logger.error('Error loading runbooks', error);
    }
  }

  private createDefaultRunbooks(): void {
    // Default runbooks for common scenarios
    const defaultRunbooks: Runbook[] = [
      // 1. Service Management
      {
        id: 'rb-service-stopped',
        name: 'Service Stopped Unexpectedly',
        description: 'Automatically restart services that stop unexpectedly',
        priority: 'high',
        requiresApproval: false,
        triggers: [
          {
            logName: 'System',
            eventId: 7034,
            level: 'Error',
            messagePattern: 'terminated unexpectedly'
          },
          {
            logName: 'System',
            eventId: 7031,
            level: 'Error'
          }
        ],
        steps: [
          {
            type: 'diagnostic',
            action: 'get-service-status',
            params: {}
          },
          {
            type: 'service',
            action: 'start',
            params: {
              serviceName: '{eventData.serviceName}'
            },
            timeout: 30000
          },
          {
            type: 'diagnostic',
            action: 'verify-service-running',
            params: {}
          }
        ]
      },
      
      // 2. Disk Space
      {
        id: 'rb-disk-space-low',
        name: 'Low Disk Space',
        description: 'Clean up temporary files when disk space is low',
        priority: 'medium',
        requiresApproval: false,
        triggers: [
          {
            logName: 'System',
            eventId: 2013,
            level: 'Warning',
            messagePattern: 'low on disk space'
          }
        ],
        steps: [
          {
            type: 'diagnostic',
            action: 'disk',
            params: {}
          },
          {
            type: 'powershell',
            action: 'Remove-Item "$env:TEMP\\*" -Recurse -Force -ErrorAction SilentlyContinue',
            params: {}
          },
          {
            type: 'powershell',
            action: 'Remove-Item "C:\\Windows\\Temp\\*" -Recurse -Force -ErrorAction SilentlyContinue',
            params: {}
          },
          {
            type: 'powershell',
            action: 'cleanmgr.exe /sagerun:1',
            params: {}
          }
        ]
      },
      
      // 3. Disk Errors
      {
        id: 'rb-disk-error',
        name: 'Disk Error Detected',
        description: 'Run disk diagnostics and attempt repair when disk errors occur',
        priority: 'critical',
        requiresApproval: true,
        triggers: [
          {
            logName: 'System',
            eventId: 7,
            level: 'Error',
            source: 'disk'
          },
          {
            logName: 'System',
            eventId: 11,
            level: 'Warning',
            source: 'disk'
          },
          {
            logName: 'System',
            eventId: 15,
            level: 'Warning',
            messagePattern: 'bad block'
          }
        ],
        steps: [
          {
            type: 'diagnostic',
            action: 'disk',
            params: {}
          },
          {
            type: 'powershell',
            action: 'Get-PhysicalDisk | Get-StorageReliabilityCounter',
            params: {}
          }
        ]
      },
      
      // 4. Memory Issues
      {
        id: 'rb-memory-high',
        name: 'High Memory Usage',
        description: 'Identify and handle high memory usage',
        priority: 'high',
        requiresApproval: false,
        triggers: [
          {
            logName: 'System',
            eventId: 2004,
            level: 'Warning',
            messagePattern: 'resource exhaustion'
          },
          {
            logName: 'System',
            eventId: 333,
            level: 'Warning'
          }
        ],
        steps: [
          {
            type: 'powershell',
            action: 'Get-Process | Sort-Object -Property WS -Descending | Select-Object -First 10',
            params: {}
          },
          {
            type: 'diagnostic',
            action: 'system',
            params: {}
          }
        ]
      },
      
      // 5. CPU High Usage
      {
        id: 'rb-cpu-high',
        name: 'High CPU Usage',
        description: 'Identify processes causing high CPU usage',
        priority: 'medium',
        requiresApproval: false,
        triggers: [
          {
            logName: 'System',
            eventId: 2020,
            level: 'Warning'
          }
        ],
        steps: [
          {
            type: 'powershell',
            action: 'Get-Process | Sort-Object -Property CPU -Descending | Select-Object -First 10 Name, CPU, Id',
            params: {}
          },
          {
            type: 'powershell',
            action: 'Get-Counter "\\Processor(_Total)\\% Processor Time"',
            params: {}
          }
        ]
      },
      
      // 6. Application Crash
      {
        id: 'rb-application-crash',
        name: 'Application Crash',
        description: 'Collect crash diagnostics and restart application',
        priority: 'medium',
        requiresApproval: true,
        triggers: [
          {
            logName: 'Application',
            eventId: 1000,
            level: 'Error',
            messagePattern: 'Faulting application'
          },
          {
            logName: 'Application',
            eventId: 1001,
            level: 'Error'
          }
        ],
        steps: [
          {
            type: 'diagnostic',
            action: 'collect-crash-dump',
            params: {}
          },
          {
            type: 'powershell',
            action: 'Get-EventLog -LogName Application -Newest 50 -EntryType Error',
            params: {}
          }
        ]
      },
      
      // 7. Network Adapter Issues
      {
        id: 'rb-network-adapter-issue',
        name: 'Network Adapter Issue',
        description: 'Reset network adapter when connectivity issues detected',
        priority: 'high',
        requiresApproval: false,
        triggers: [
          {
            logName: 'System',
            eventId: 4202,
            level: 'Warning'
          },
          {
            logName: 'System',
            eventId: 27,
            level: 'Error',
            source: 'e1iexpress'
          }
        ],
        steps: [
          {
            type: 'diagnostic',
            action: 'network',
            params: {}
          },
          {
            type: 'powershell',
            action: 'ipconfig /release',
            params: {}
          },
          {
            type: 'powershell',
            action: 'ipconfig /renew',
            params: {}
          },
          {
            type: 'powershell',
            action: 'ipconfig /flushdns',
            params: {}
          }
        ]
      },
      
      // 8. DNS Issues
      {
        id: 'rb-dns-failure',
        name: 'DNS Resolution Failure',
        description: 'Fix DNS resolution issues',
        priority: 'high',
        requiresApproval: false,
        triggers: [
          {
            logName: 'System',
            eventId: 1014,
            level: 'Warning',
            source: 'DNS Client Events'
          },
          {
            logName: 'Application',
            eventId: 1000,
            messagePattern: 'DNS.*failed'
          }
        ],
        steps: [
          {
            type: 'powershell',
            action: 'ipconfig /flushdns',
            params: {}
          },
          {
            type: 'powershell',
            action: 'Clear-DnsClientCache',
            params: {}
          },
          {
            type: 'service',
            action: 'restart',
            params: {
              serviceName: 'Dnscache'
            }
          }
        ]
      },
      
      // 9. Windows Update Issues
      {
        id: 'rb-windows-update-failed',
        name: 'Windows Update Failed',
        description: 'Troubleshoot failed Windows updates',
        priority: 'medium',
        requiresApproval: false,
        triggers: [
          {
            logName: 'System',
            eventId: 20,
            level: 'Error',
            source: 'Microsoft-Windows-WindowsUpdateClient'
          },
          {
            logName: 'System',
            eventId: 44,
            level: 'Error',
            source: 'Microsoft-Windows-WindowsUpdateClient'
          }
        ],
        steps: [
          {
            type: 'service',
            action: 'stop',
            params: {
              serviceName: 'wuauserv'
            }
          },
          {
            type: 'powershell',
            action: 'Remove-Item "C:\\Windows\\SoftwareDistribution\\Download\\*" -Recurse -Force -ErrorAction SilentlyContinue',
            params: {}
          },
          {
            type: 'service',
            action: 'start',
            params: {
              serviceName: 'wuauserv'
            }
          }
        ]
      },
      
      // 10. System Reboot Required
      {
        id: 'rb-reboot-required',
        name: 'System Reboot Required',
        description: 'System requires restart for updates or stability',
        priority: 'low',
        requiresApproval: true,
        triggers: [
          {
            logName: 'System',
            eventId: 1074,
            level: 'Information',
            messagePattern: 'restart'
          }
        ],
        steps: [
          {
            type: 'diagnostic',
            action: 'system',
            params: {}
          }
        ]
      },
      
      // 11. Print Spooler Issues
      {
        id: 'rb-print-spooler',
        name: 'Print Spooler Stopped',
        description: 'Restart print spooler and clear stuck jobs',
        priority: 'medium',
        requiresApproval: false,
        triggers: [
          {
            logName: 'System',
            eventId: 7031,
            level: 'Error',
            messagePattern: 'Print Spooler'
          }
        ],
        steps: [
          {
            type: 'service',
            action: 'stop',
            params: {
              serviceName: 'Spooler'
            }
          },
          {
            type: 'powershell',
            action: 'Remove-Item "C:\\Windows\\System32\\spool\\PRINTERS\\*" -Force -ErrorAction SilentlyContinue',
            params: {}
          },
          {
            type: 'service',
            action: 'start',
            params: {
              serviceName: 'Spooler'
            }
          }
        ]
      },
      
      // 12. Time Sync Issues
      {
        id: 'rb-time-sync',
        name: 'Time Synchronization Failed',
        description: 'Fix Windows Time service synchronization',
        priority: 'low',
        requiresApproval: false,
        triggers: [
          {
            logName: 'System',
            eventId: 134,
            level: 'Warning',
            source: 'Microsoft-Windows-Time-Service'
          },
          {
            logName: 'System',
            eventId: 35,
            level: 'Error',
            source: 'Microsoft-Windows-Time-Service'
          }
        ],
        steps: [
          {
            type: 'powershell',
            action: 'w32tm /resync /force',
            params: {}
          },
          {
            type: 'service',
            action: 'restart',
            params: {
              serviceName: 'W32Time'
            }
          }
        ]
      }
    ];

    // Save default runbooks
    for (const runbook of defaultRunbooks) {
      const filePath = path.join(this.runbooksPath, `${runbook.id}.json`);
      fs.writeFileSync(filePath, JSON.stringify(runbook, null, 2));
      this.runbooks.set(runbook.id, runbook);
    }

    this.logger.info('Created default runbooks', { count: defaultRunbooks.length });
  }

  public addRunbook(runbook: Runbook): void {
    this.runbooks.set(runbook.id, runbook);
    
    const filePath = path.join(this.runbooksPath, `${runbook.id}.json`);
    fs.writeFileSync(filePath, JSON.stringify(runbook, null, 2));
    
    this.logger.info('Added new runbook', { id: runbook.id, name: runbook.name });
  }

  // ============================================
  // EVENT LOG MONITORING
  // ============================================

  public startMonitoring(intervalSeconds: number = 30): void {
    if (this.isMonitoring) {
      this.logger.warn('Event monitoring already started');
      return;
    }

    this.isMonitoring = true;
    this.logger.info('Starting event log monitoring', { interval: intervalSeconds });

    // Initial check
    this.checkEventLogs();

    // Set up periodic checking
    this.monitoringInterval = setInterval(() => {
      this.checkEventLogs();
    }, intervalSeconds * 1000);
  }

  public stopMonitoring(): void {
    if (!this.isMonitoring) {
      return;
    }

    this.isMonitoring = false;
    
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
      this.monitoringInterval = null;
    }

    this.logger.info('Stopped event log monitoring');
  }

  private async checkEventLogs(): Promise<void> {
    this.logger.info('Checking event logs...', { 
      lastChecked: this.lastCheckedTime.toISOString() 
    });
    
    try {
      const logs = ['System', 'Application'];
      
      for (const logName of logs) {
        this.logger.debug(`Starting check of ${logName} log`);
        await this.checkLog(logName);
      }

      this.lastCheckedTime = new Date();
      this.logger.info('Event log check complete', {
        nextCheck: new Date(Date.now() + 30000).toISOString()
      });
    } catch (error) {
      this.logger.error('Error checking event logs', error);
    }
  }

  private async checkLog(logName: string): Promise<void> {
    try {
      // Calculate hours back from now
      const now = new Date();
      const diffMs = now.getTime() - this.lastCheckedTime.getTime();
      const hoursBack = Math.ceil(diffMs / (1000 * 60 * 60));
      
      this.logger.debug(`Checking ${logName} log for events in last ${hoursBack} hours`);
      
      // Create a temporary PowerShell script file to avoid quote escaping issues
      const tempScript = path.join(require('os').tmpdir(), `opsis-check-${logName}-${Date.now()}.ps1`);
      
      const scriptContent = `
Get-WinEvent -FilterHashtable @{LogName='${logName}'} -MaxEvents 1000 -ErrorAction SilentlyContinue | 
Where-Object { $_.TimeCreated -gt (Get-Date).AddHours(-${hoursBack}) -and $_.Level -le 3 } | 
Select-Object -First 100 | 
ConvertTo-Json -Depth 3
      `.trim();
      
      fs.writeFileSync(tempScript, scriptContent);

      this.logger.debug(`Executing PowerShell script for ${logName}`);
      
      const { stdout, stderr } = await execAsync(`powershell -ExecutionPolicy Bypass -File "${tempScript}"`);
      
      // Clean up temp file
      try {
        fs.unlinkSync(tempScript);
      } catch (e) {
        // Ignore cleanup errors
      }
      
      if (stderr) {
        this.logger.warn(`PowerShell stderr for ${logName}:`, { stderr });
      }
      
      if (!stdout.trim()) {
        this.logger.debug(`No events found in ${logName} log`);
        return; // No events
      }

      this.logger.debug(`PowerShell returned data for ${logName}, parsing...`);
      
      const events = JSON.parse(stdout);
      const eventArray = Array.isArray(events) ? events : [events];

      this.logger.info(`Found ${eventArray.length} events in ${logName} log`);

      for (const event of eventArray) {
        const entry = this.parseEvent(event, logName);
        this.logger.debug(`Processing event: ${entry.id} - ${entry.level} - ${entry.source}`);
        await this.processEvent(entry);
      }

    } catch (error: any) {
      // Log all errors for debugging
      this.logger.error(`Error checking ${logName} log`, error, {
        message: error.message,
        code: error.code
      });
    }
  }

  private parseEvent(event: any, logName: string): EventLogEntry {
    // Parse .NET JSON date format: /Date(1768311870877)/
    let timeCreated: Date;
    if (typeof event.TimeCreated === 'string' && event.TimeCreated.startsWith('/Date(')) {
      const timestamp = parseInt(event.TimeCreated.match(/\d+/)[0]);
      timeCreated = new Date(timestamp);
    } else {
      timeCreated = new Date(event.TimeCreated);
    }

    return {
      timeCreated: timeCreated,
      id: event.Id,
      level: this.getLevelName(event.Level),
      source: event.ProviderName,
      message: event.Message || '',
      computer: event.MachineName,
      logName: logName,
      raw: event
    };
  }

  private getLevelName(level: number): string {
    switch (level) {
      case 1: return 'Critical';
      case 2: return 'Error';
      case 3: return 'Warning';
      case 4: return 'Information';
      default: return 'Unknown';
    }
  }

  // ============================================
  // EVENT PROCESSING & RUNBOOK MATCHING
  // ============================================

  private async processEvent(event: EventLogEntry): Promise<void> {
    // Log the event
    this.logger.debug('Event detected', {
      id: event.id,
      level: event.level,
      source: event.source,
      message: event.message.substring(0, 100)
    });

    // Skip non-critical events
    if (event.level === 'Information') {
      return;
    }

    // Extract additional data from event (like service names)
    const eventData = this.extractEventData(event);

    // Try to match a runbook
    const match = this.matchRunbook(event);

    if (match) {
      this.logger.info('Runbook matched for event', {
        eventId: event.id,
        runbookId: match.runbookId,
        confidence: match.confidence,
        eventData
      });

      // Check if this requires special approval (protected services)
      const requiresApproval = this.requiresApproval(event, eventData, match);

      // Enhance runbook steps with extracted data
      const enhancedSteps = this.enhanceStepsWithEventData(match.steps, eventData);

      // Trigger issue detection with enhanced runbook
      const enhancedMatch = { ...match, steps: enhancedSteps };
      this.onIssueDetected(event, enhancedMatch);
    } else {
      // No runbook found - check if we should escalate
      await this.handleUnmatchedEvent(event);
    }
  }

  private extractEventData(event: EventLogEntry): Record<string, any> {
    const data: Record<string, any> = {};

    // Extract service name from Event ID 7034, 7031, 7036 messages
    if ([7034, 7031, 7036].includes(event.id)) {
      const serviceNameMatch = event.message.match(/The (.+?) service/i);
      if (serviceNameMatch) {
        data.serviceName = serviceNameMatch[1].trim();
        this.logger.debug('Extracted service name', { serviceName: data.serviceName });
      }
    }

    // Extract application name from crash events (1000, 1001)
    if ([1000, 1001].includes(event.id)) {
      const appNameMatch = event.message.match(/Faulting application name: (.+?),/i);
      if (appNameMatch) {
        data.applicationName = appNameMatch[1].trim();
      }
    }

    // Extract disk information from disk events
    if ([7, 11, 15, 2013].includes(event.id)) {
      const driveMatch = event.message.match(/drive ([A-Z]:)/i);
      if (driveMatch) {
        data.driveLetter = driveMatch[1];
      }
    }

    return data;
  }

  private enhanceStepsWithEventData(
    steps: RunbookStep[], 
    eventData: Record<string, any>
  ): RunbookStep[] {
    return steps.map(step => {
      const enhancedStep = { ...step };
      
      // Replace placeholders in params
      if (step.params) {
        enhancedStep.params = { ...step.params };
        
        for (const [key, value] of Object.entries(enhancedStep.params)) {
          if (typeof value === 'string') {
            // Replace {eventData.serviceName} with actual service name
            let replacedValue = value;
            for (const [dataKey, dataValue] of Object.entries(eventData)) {
              const placeholder = `{eventData.${dataKey}}`;
              if (replacedValue.includes(placeholder)) {
                replacedValue = replacedValue.replace(placeholder, dataValue as string);
              }
            }
            enhancedStep.params[key] = replacedValue;
          }
        }
      }
      
      // FIXED: Convert service action steps to use PowerShell instead of net.exe
      // PowerShell Start-Service accepts both service names and display names
      if (step.type === 'service') {
        // Keep the params as-is - PowerShell will handle display names
        this.logger.debug('Service action step will use PowerShell', {
          action: step.action,
          serviceName: enhancedStep.params.serviceName
        });
      }

      return enhancedStep;
    });
  }

  private requiresApproval(
    event: EventLogEntry, 
    eventData: Record<string, any>,
    match: RunbookMatch
  ): boolean {
    // Critical/protected services that should require approval
    const protectedServices = [
      // Active Directory
      'NTDS',
      'DNS',
      'DFSR',
      'Netlogon',
      'KDC',
      
      // SQL Server
      'MSSQLSERVER',
      'SQLSERVERAGENT',
      'SQLBrowser',
      'MSSQLFDLauncher',
      
      // Exchange
      'MSExchangeTransport',
      'MSExchangeIS',
      'MSExchangeADTopology',
      
      // IIS
      'W3SVC',
      'WAS',
      
      // Hyper-V
      'vmms',
      'vmcompute',
      
      // Backup Services
      'VSS',
      'wbengine',
      
      // Security
      'mpssvc', // Windows Firewall
      'WinDefend',
      'SecurityHealthService',
      
      // System Critical
      'RpcSs',
      'Dhcp',
      'EventLog',
      'WinRM',
      'W32Time'
    ];

    // Check if service is protected
    if (eventData.serviceName) {
      const isProtected = protectedServices.some(svc => 
        eventData.serviceName.toLowerCase().includes(svc.toLowerCase())
      );
      
      if (isProtected) {
        this.logger.warn('Protected service detected - requires approval', {
          serviceName: eventData.serviceName
        });
        return true;
      }
    }

    // Also respect runbook's requiresApproval setting
    return match.steps.some(step => step.requiresApproval);
  }

  private matchRunbook(event: EventLogEntry): RunbookMatch | null {
    let bestMatch: { runbook: Runbook; confidence: number; trigger: string } | null = null;

    for (const [id, runbook] of this.runbooks) {
      for (const trigger of runbook.triggers) {
        const confidence = this.calculateMatchConfidence(event, trigger);

        if (confidence > 0 && (!bestMatch || confidence > bestMatch.confidence)) {
          bestMatch = {
            runbook,
            confidence,
            trigger: this.describeTrigger(trigger)
          };
        }
      }
    }

    if (bestMatch && bestMatch.confidence >= 0.7) {
      return {
        runbookId: bestMatch.runbook.id,
        name: bestMatch.runbook.name,
        confidence: bestMatch.confidence,
        trigger: bestMatch.trigger,
        steps: bestMatch.runbook.steps
      };
    }

    return null;
  }

  private calculateMatchConfidence(event: EventLogEntry, trigger: RunbookTrigger): number {
    let score = 0;
    let checks = 0;

    // Log name match (required)
    if (trigger.logName !== event.logName) {
      return 0;
    }
    score += 1;
    checks += 1;

    // Event ID match (strong indicator)
    if (trigger.eventId !== undefined) {
      checks += 1;
      if (trigger.eventId === event.id) {
        score += 1;
      } else {
        return 0; // Event ID mismatch is fatal
      }
    }

    // Level match
    if (trigger.level !== undefined) {
      checks += 1;
      if (trigger.level === event.level) {
        score += 0.5;
      }
    }

    // Source match
    if (trigger.source !== undefined) {
      checks += 1;
      if (trigger.source === event.source) {
        score += 0.5;
      }
    }

    // Message pattern match
    if (trigger.messagePattern !== undefined) {
      checks += 1;
      try {
        const regex = new RegExp(trigger.messagePattern, 'i');
        if (regex.test(event.message)) {
          score += 1;
        }
      } catch (error) {
        this.logger.warn('Invalid regex pattern', { pattern: trigger.messagePattern });
      }
    }

    return checks > 0 ? score / checks : 0;
  }

  private describeTrigger(trigger: RunbookTrigger): string {
    const parts: string[] = [];
    
    parts.push(`Log: ${trigger.logName}`);
    if (trigger.eventId) parts.push(`Event: ${trigger.eventId}`);
    if (trigger.level) parts.push(`Level: ${trigger.level}`);
    if (trigger.source) parts.push(`Source: ${trigger.source}`);
    
    return parts.join(', ');
  }

  // ============================================
  // ESCALATION CHAIN
  // ============================================

  private async handleUnmatchedEvent(event: EventLogEntry): Promise<void> {
    // Critical and Error events without runbooks should be escalated
    if (event.level === 'Critical' || event.level === 'Error') {
      
      this.logger.info('No runbook found for critical/error event - requesting escalation', {
        eventId: event.id,
        level: event.level,
        source: event.source
      });

      // Request server to create runbook or escalate
      const reason = this.analyzeEventForEscalation(event);
      this.onEscalationNeeded(event, reason);
    }
  }

  private analyzeEventForEscalation(event: EventLogEntry): string {
    const reasons: string[] = [];

    // Determine why this needs escalation
    if (event.level === 'Critical') {
      reasons.push('Critical severity event');
    }

    if (this.isRepeatedEvent(event)) {
      reasons.push('Recurring issue - seen multiple times');
    }

    if (this.isSystemCritical(event)) {
      reasons.push('Affects critical system component');
    }

    if (reasons.length === 0) {
      reasons.push('No matching runbook available');
    }

    return reasons.join('; ');
  }

  private isRepeatedEvent(event: EventLogEntry): boolean {
    // TODO: Implement history tracking
    // Check if same event ID has occurred multiple times recently
    return false;
  }

  private isSystemCritical(event: EventLogEntry): boolean {
    const criticalSources = [
      'Service Control Manager',
      'disk',
      'volsnap',
      'ntfs',
      'Kernel-Power'
    ];

    return criticalSources.some(source => 
      event.source.toLowerCase().includes(source.toLowerCase())
    );
  }

  // ============================================
  // STATISTICS & REPORTING
  // ============================================

  public getStatistics(): any {
    return {
      isMonitoring: this.isMonitoring,
      runbooksLoaded: this.runbooks.size,
      lastChecked: this.lastCheckedTime,
      runbooks: Array.from(this.runbooks.values()).map(rb => ({
        id: rb.id,
        name: rb.name,
        priority: rb.priority,
        triggers: rb.triggers.length
      }))
    };
  }
}

export default EventMonitor;
