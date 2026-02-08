/**
 * OPSIS Agent Self-Service Conversation Engine
 * State-machine driven conversation that classifies user problems,
 * runs diagnostics, interprets results, and proposes fixes.
 */

import { Logger } from '../common/logger';
import { TroubleshootingRunner, IssueCategory, DiagnosticData } from './troubleshooting-runner';
import { Primitives } from '../execution/primitives';
import { ActionTicketManager } from './action-ticket-manager';
import { TicketDatabase } from './ticket-database';

// Conversation states
type SessionState =
  | 'GREETING'
  | 'PROBLEM_DESCRIPTION'
  | 'FOLLOW_UP'
  | 'RUNNING_DIAGNOSTICS'
  | 'PRESENTING_FINDINGS'
  | 'AWAITING_APPROVAL'
  | 'EXECUTING_FIX'
  | 'AWAITING_ESCALATION'
  | 'COMPLETED';

export interface Finding {
  severity: 'info' | 'warning' | 'critical';
  summary: string;
  details: string;
  fixAvailable: boolean;
  fixDescription?: string;
  fixAction?: FixAction;
}

export interface FixAction {
  type: 'primitive';
  primitive: string;
  params: Record<string, any>;
  riskDescription: string;
}

export interface ConversationCallback {
  sendMessage: (text: string, metadata?: any) => void;
  sendProgress: (step: number, total: number, description: string) => void;
  sendFindings: (findings: Finding[]) => void;
  sendFixResult: (success: boolean, message: string) => void;
  sendSatisfactionPrompt: () => void;
  requestEscalation: (data: {
    user_description: string;
    category: string;
    diagnostic_data: any;
  }) => Promise<{
    analysis: string;
    suggested_fix?: { type: string; primitive?: string; params?: Record<string, any> };
    suggested_fix_description?: string;
  } | null>;
}

interface ConversationSession {
  id: string;
  state: SessionState;
  category: IssueCategory | null;
  userDescription: string;
  followUpAnswers: string[];
  followUpIndex: number;
  diagnosticData: DiagnosticData | null;
  findings: Finding[];
  callback: ConversationCallback;
  startedAt: number;
  ticketId?: string;
  fixApplied?: string;
  messageCount: number;
}

// Problem patterns for keyword classification
interface ProblemPattern {
  category: IssueCategory;
  keywords: string[];
  followUpQuestions: string[];
  friendlyName: string;
}

const PROBLEM_PATTERNS: ProblemPattern[] = [
  {
    category: 'cpu',
    keywords: [
      'slow', 'sluggish', 'laggy', 'lagging', 'unresponsive', 'freezing', 'frozen',
      'hanging', 'hung', 'not responding', 'takes forever', 'fan loud', 'fan spinning',
      'hot', 'overheating', 'high cpu', 'spinning', 'programs slow', 'computer slow',
      'everything slow', 'really slow', 'super slow', 'so slow', 'running slow'
    ],
    followUpQuestions: [
      'Is it one specific program that\'s slow, or the whole computer?'
    ],
    friendlyName: 'Performance / Slowness'
  },
  {
    category: 'memory',
    keywords: [
      'out of memory', 'low memory', 'memory full', 'ram', 'programs closing',
      'programs crashing', 'crashing', 'crash', 'not enough memory', 'ran out of resources',
      'low on resources', 'resource exhausted', 'memory warning', 'memory error'
    ],
    followUpQuestions: [
      'Are specific programs crashing, or is the whole computer affected?'
    ],
    friendlyName: 'Memory Issues'
  },
  {
    category: 'disk',
    keywords: [
      'disk full', 'no space', 'storage full', 'drive full', 'cannot save', 'can\'t save',
      'low disk', 'red bar', 'c: drive', 'c drive', 'out of space', 'need more space',
      'disk error', 'storage', 'hard drive full', 'no room', 'space running out'
    ],
    followUpQuestions: [
      'Did this happen suddenly, or has it been building up over time?'
    ],
    friendlyName: 'Disk Space / Storage'
  },
  {
    category: 'network',
    keywords: [
      'internet', 'wifi', 'wi-fi', 'network', 'cannot connect', 'can\'t connect',
      'no connection', 'no internet', 'slow internet', 'website not loading', 'pages not loading',
      'dns', 'vpn', 'disconnecting', 'keeps disconnecting', 'ethernet', 'offline',
      'no network', 'connection dropped', 'can\'t reach'
    ],
    followUpQuestions: [
      'Are all websites affected, or just specific ones?'
    ],
    friendlyName: 'Network / Internet'
  },
  {
    category: 'service',
    keywords: [
      'printer', 'print', 'printing', 'spooler', 'can\'t print', 'cannot print',
      'service stopped', 'windows update', 'update failed', 'updates', 'update stuck',
      'app not starting', 'application not starting', 'won\'t open', 'won\'t start',
      'feature not working', 'outlook', 'teams', 'excel', 'word'
    ],
    followUpQuestions: [
      'Which service or program is not working correctly?'
    ],
    friendlyName: 'Service / Application Issue'
  }
];

// Quick-pick categories exposed to the frontend
const QUICK_PICKS: Record<string, { category: IssueCategory; description: string }> = {
  'slow-computer': { category: 'cpu', description: 'My computer is slow' },
  'no-internet': { category: 'network', description: 'I have no internet' },
  'cant-print': { category: 'service', description: 'I can\'t print' },
  'disk-full': { category: 'disk', description: 'My disk is full' },
  'programs-crashing': { category: 'memory', description: 'Programs keep crashing' },
  'other': { category: 'general', description: 'Something else' }
};

export class ConversationEngine {
  private logger: Logger;
  private troubleshootingRunner: TroubleshootingRunner;
  private primitives: Primitives;
  private actionTicketManager: ActionTicketManager;
  private ticketDb: TicketDatabase;
  private sessions: Map<string, ConversationSession> = new Map();

  constructor(
    logger: Logger,
    troubleshootingRunner: TroubleshootingRunner,
    primitives: Primitives,
    actionTicketManager: ActionTicketManager,
    ticketDb: TicketDatabase
  ) {
    this.logger = logger;
    this.troubleshootingRunner = troubleshootingRunner;
    this.primitives = primitives;
    this.actionTicketManager = actionTicketManager;
    this.ticketDb = ticketDb;
  }

  createSession(sessionId: string, callback: ConversationCallback): void {
    const session: ConversationSession = {
      id: sessionId,
      state: 'GREETING',
      category: null,
      userDescription: '',
      followUpAnswers: [],
      followUpIndex: 0,
      diagnosticData: null,
      findings: [],
      callback,
      startedAt: Date.now(),
      messageCount: 0
    };

    this.sessions.set(sessionId, session);

    // Send greeting
    callback.sendMessage(
      'Hi! I\'m your IT assistant. Tell me what\'s going on, or pick one of the common issues below.',
      { quickPicks: Object.entries(QUICK_PICKS).map(([id, qp]) => ({ id, label: qp.description })) }
    );

    session.state = 'PROBLEM_DESCRIPTION';
  }

  endSession(sessionId: string): void {
    this.sessions.delete(sessionId);
  }

  async processMessage(sessionId: string, text: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session) return;

    session.messageCount++;

    switch (session.state) {
      case 'PROBLEM_DESCRIPTION':
        await this.handleProblemDescription(session, text);
        break;

      case 'FOLLOW_UP':
        await this.handleFollowUp(session, text);
        break;

      case 'PRESENTING_FINDINGS':
      case 'AWAITING_APPROVAL':
        // User typed instead of clicking a button
        const lower = text.toLowerCase();
        if (lower.includes('yes') || lower.includes('fix') || lower.includes('ok') || lower.includes('do it')) {
          await this.approveFix(sessionId, 0);
        } else if (lower.includes('no') || lower.includes('skip') || lower.includes('cancel')) {
          await this.declineFix(sessionId);
        } else {
          session.callback.sendMessage('Would you like me to apply the fix? You can click "Fix it" or say "yes" / "no".');
        }
        break;

      case 'COMPLETED':
        session.callback.sendMessage('This session is complete. Refresh the page to start a new one.');
        break;

      default:
        // Ignore messages during diagnostics/execution
        break;
    }
  }

  async processQuickPick(sessionId: string, pickId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session || session.state !== 'PROBLEM_DESCRIPTION') return;

    const pick = QUICK_PICKS[pickId];
    if (!pick) return;

    session.userDescription = pick.description;
    session.category = pick.category;

    session.callback.sendMessage(
      `Got it — "${pick.description}". Let me run some diagnostics on your system. This usually takes about 15 seconds...`
    );

    await this.runDiagnostics(session);
  }

  async approveFix(sessionId: string, fixIndex: number): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session || (session.state !== 'PRESENTING_FINDINGS' && session.state !== 'AWAITING_APPROVAL')) return;

    const finding = session.findings[fixIndex];
    if (!finding || !finding.fixAction) {
      session.callback.sendMessage('That fix is no longer available.');
      return;
    }

    session.state = 'EXECUTING_FIX';
    session.callback.sendMessage(`Applying fix: ${finding.fixDescription}...`);

    try {
      const result = await this.executeFix(finding.fixAction);
      session.fixApplied = `${finding.fixAction.primitive}:${JSON.stringify(finding.fixAction.params)}`;

      if (result.success) {
        session.callback.sendFixResult(true, `Done! ${result.message}`);

        // Create ticket
        session.ticketId = this.createSelfServiceTicket(session, finding, true);

        session.callback.sendMessage('Is your issue resolved? Please rate your experience:');
        session.callback.sendSatisfactionPrompt();
        session.state = 'COMPLETED';
      } else {
        session.callback.sendFixResult(false, `The fix didn't work as expected: ${result.message}`);
        session.callback.sendMessage('I recommend contacting the helpdesk for further assistance.');

        session.ticketId = this.createSelfServiceTicket(session, finding, false);
        session.state = 'COMPLETED';
        session.callback.sendSatisfactionPrompt();
      }
    } catch (error: any) {
      this.logger.error('Self-service fix execution error', { error: error.message, sessionId });
      session.callback.sendFixResult(false, 'Something went wrong while applying the fix.');
      session.callback.sendMessage('I recommend contacting the helpdesk for further assistance.');
      session.state = 'COMPLETED';
      session.callback.sendSatisfactionPrompt();
    }
  }

  async declineFix(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session) return;

    session.callback.sendMessage(
      'No problem! If the issue persists, feel free to come back or contact the helpdesk.'
    );

    // Still create a ticket for tracking (no fix applied)
    session.ticketId = this.createSelfServiceTicket(session, null, false);

    session.callback.sendMessage('Please rate your experience:');
    session.callback.sendSatisfactionPrompt();
    session.state = 'COMPLETED';
  }

  completeSatisfaction(sessionId: string, rating: number): {
    category: string;
    resolution_time_seconds: number;
    user_satisfaction: number;
    fix_applied?: string;
    auto_resolved: boolean;
    session_messages: number;
    ticket_id?: string;
  } | null {
    const session = this.sessions.get(sessionId);
    if (!session) return null;

    const resolution = {
      category: session.category || 'general',
      resolution_time_seconds: Math.round((Date.now() - session.startedAt) / 1000),
      user_satisfaction: rating,
      fix_applied: session.fixApplied,
      auto_resolved: !!session.fixApplied,
      session_messages: session.messageCount,
      ticket_id: session.ticketId
    };

    session.callback.sendMessage(
      rating >= 4
        ? 'Thank you! Glad I could help.'
        : 'Thank you for the feedback. We\'ll work on improving.'
    );

    return resolution;
  }

  handleEscalationResponse(sessionId: string, response: any): void {
    const session = this.sessions.get(sessionId);
    if (!session || session.state !== 'AWAITING_ESCALATION') return;

    if (response && response.analysis) {
      session.callback.sendMessage(response.analysis);

      if (response.suggested_fix && response.suggested_fix_description) {
        const finding: Finding = {
          severity: 'warning',
          summary: response.analysis,
          details: response.suggested_fix_description,
          fixAvailable: true,
          fixDescription: response.suggested_fix_description,
          fixAction: {
            type: 'primitive',
            primitive: response.suggested_fix.primitive,
            params: response.suggested_fix.params || {},
            riskDescription: response.suggested_fix_description
          }
        };
        session.findings = [finding];
        session.callback.sendFindings([finding]);
        session.state = 'AWAITING_APPROVAL';
      } else {
        session.callback.sendMessage('I recommend contacting the helpdesk for further hands-on assistance.');
        session.state = 'COMPLETED';
        session.callback.sendSatisfactionPrompt();
      }
    } else {
      session.callback.sendMessage(
        'I wasn\'t able to determine the exact issue. Please contact the helpdesk for further assistance.'
      );
      session.state = 'COMPLETED';
      session.callback.sendSatisfactionPrompt();
    }
  }

  // --- Private methods ---

  private async handleProblemDescription(session: ConversationSession, text: string): Promise<void> {
    session.userDescription = text;

    // Classify the problem
    const classification = this.classifyProblem(text);
    session.category = classification.category;

    if (classification.confidence >= 0.6) {
      // Good match — ask one follow-up then run diagnostics
      const pattern = PROBLEM_PATTERNS.find(p => p.category === classification.category);
      if (pattern && pattern.followUpQuestions.length > 0) {
        session.state = 'FOLLOW_UP';
        session.followUpIndex = 0;
        session.callback.sendMessage(
          `Sounds like a ${pattern.friendlyName.toLowerCase()} issue. ${pattern.followUpQuestions[0]}`
        );
      } else {
        session.callback.sendMessage(
          'Let me run some diagnostics on your system. This usually takes about 15 seconds...'
        );
        await this.runDiagnostics(session);
      }
    } else {
      // Low confidence — run general diagnostics
      session.category = 'general';
      session.callback.sendMessage(
        'I\'ll run a general health check on your system to see what\'s going on. This usually takes about 15 seconds...'
      );
      await this.runDiagnostics(session);
    }
  }

  private async handleFollowUp(session: ConversationSession, text: string): Promise<void> {
    session.followUpAnswers.push(text);
    session.followUpIndex++;

    const pattern = PROBLEM_PATTERNS.find(p => p.category === session.category);
    if (pattern && session.followUpIndex < pattern.followUpQuestions.length) {
      // More follow-up questions
      session.callback.sendMessage(pattern.followUpQuestions[session.followUpIndex]);
    } else {
      // Done with follow-ups, run diagnostics
      session.callback.sendMessage(
        'Thanks for the info. Running diagnostics now — this usually takes about 15 seconds...'
      );
      await this.runDiagnostics(session);
    }
  }

  private classifyProblem(text: string): { category: IssueCategory; confidence: number } {
    const lower = text.toLowerCase();
    const scores: Map<IssueCategory, number> = new Map();

    for (const pattern of PROBLEM_PATTERNS) {
      let matchCount = 0;
      for (const keyword of pattern.keywords) {
        if (lower.includes(keyword)) {
          matchCount++;
        }
      }
      if (matchCount > 0) {
        scores.set(pattern.category, matchCount / pattern.keywords.length);
      }
    }

    if (scores.size === 0) {
      return { category: 'general', confidence: 0.3 };
    }

    // Return highest scoring category
    let bestCategory: IssueCategory = 'general';
    let bestScore = 0;
    for (const [cat, score] of scores) {
      if (score > bestScore) {
        bestScore = score;
        bestCategory = cat;
      }
    }

    // Boost confidence for multi-keyword matches
    const confidence = Math.min(0.5 + bestScore * 5, 1.0);
    return { category: bestCategory, confidence };
  }

  private async runDiagnostics(session: ConversationSession): Promise<void> {
    session.state = 'RUNNING_DIAGNOSTICS';
    const category = session.category || 'general';

    this.logger.info('Self-service running diagnostics', {
      sessionId: session.id,
      category
    });

    try {
      // Build params from follow-up answers
      const params: Record<string, any> = {};
      if (category === 'disk') {
        params.target_drive = 'C:';
      }
      if (category === 'service') {
        // Try to extract service name from description or follow-up
        const serviceHint = this.extractServiceHint(session);
        if (serviceHint) {
          params.target_service = serviceHint;
        }
      }

      // Run diagnostics with progress callbacks
      const diagnosticData = await this.troubleshootingRunner.runByCategory(
        category,
        params,
        20000,
        (step, total, description) => {
          session.callback.sendProgress(step, total, description);
        }
      );

      if (!diagnosticData) {
        session.callback.sendMessage(
          'I wasn\'t able to run the diagnostics. Please contact the helpdesk for assistance.'
        );
        session.state = 'COMPLETED';
        session.callback.sendSatisfactionPrompt();
        return;
      }

      session.diagnosticData = diagnosticData;

      // Interpret the results
      const findings = this.interpretFindings(category, diagnosticData);
      session.findings = findings;

      if (findings.length === 0) {
        // No clear findings — try AI escalation
        session.callback.sendMessage('The diagnostics didn\'t reveal an obvious issue. Let me check with the server for a deeper analysis...');
        session.state = 'AWAITING_ESCALATION';

        const escalationResult = await session.callback.requestEscalation({
          user_description: session.userDescription,
          category,
          diagnostic_data: diagnosticData
        });

        if (escalationResult) {
          this.handleEscalationResponse(session.id, escalationResult);
        } else {
          session.callback.sendMessage(
            'I wasn\'t able to identify a specific issue. Your system appears to be running normally. If the problem persists, please contact the helpdesk.'
          );
          session.state = 'COMPLETED';
          session.callback.sendSatisfactionPrompt();
        }
        return;
      }

      // Present findings
      session.state = 'PRESENTING_FINDINGS';
      session.callback.sendFindings(findings);

      // Summarize in chat
      const fixable = findings.filter(f => f.fixAvailable);
      if (fixable.length > 0) {
        session.callback.sendMessage(
          `I found ${findings.length} issue${findings.length > 1 ? 's' : ''}. ` +
          `${fixable.length > 0 ? 'I can fix ' + (fixable.length === 1 ? 'this' : 'some of these') + ' for you.' : ''}`
        );
        session.state = 'AWAITING_APPROVAL';
      } else {
        session.callback.sendMessage(
          'I found some information about your system, but there\'s no automated fix available. ' +
          'Please contact the helpdesk if you need further assistance.'
        );
        session.state = 'COMPLETED';
        session.callback.sendSatisfactionPrompt();
      }
    } catch (error: any) {
      this.logger.error('Self-service diagnostics error', { error: error.message, sessionId: session.id });
      session.callback.sendMessage('An error occurred while running diagnostics. Please try again or contact the helpdesk.');
      session.state = 'COMPLETED';
      session.callback.sendSatisfactionPrompt();
    }
  }

  private interpretFindings(category: IssueCategory, data: DiagnosticData): Finding[] {
    const findings: Finding[] = [];
    const results = data.data;

    switch (category) {
      case 'cpu':
        this.interpretCpuFindings(results, findings);
        break;
      case 'memory':
        this.interpretMemoryFindings(results, findings);
        break;
      case 'disk':
        this.interpretDiskFindings(results, findings);
        break;
      case 'network':
        this.interpretNetworkFindings(results, findings);
        break;
      case 'service':
        this.interpretServiceFindings(results, findings);
        break;
      case 'general':
        this.interpretGeneralFindings(results, findings);
        break;
    }

    return findings;
  }

  private interpretCpuFindings(results: Record<string, any>, findings: Finding[]): void {
    const topProc = results.top_processes;
    if (!topProc?.success || !topProc.data) return;

    const processes: any[] = Array.isArray(topProc.data) ? topProc.data : [topProc.data];

    // Find processes using high CPU (> 30%)
    for (const proc of processes.slice(0, 5)) {
      if (proc.cpu_percent > 30 && proc.name.toLowerCase() !== 'idle' && proc.name.toLowerCase() !== 'system') {
        const isProtected = ['csrss', 'wininit', 'services', 'lsass', 'svchost', 'dwm', 'explorer'].includes(proc.name.toLowerCase());

        findings.push({
          severity: proc.cpu_percent > 70 ? 'critical' : 'warning',
          summary: `${proc.name} is using ${Math.round(proc.cpu_percent)}% of your CPU` +
            (proc.memory_mb > 500 ? ` and ${Math.round(proc.memory_mb)} MB of memory` : ''),
          details: `This process has been consuming significant resources.` +
            (proc.thread_count > 100 ? ` It has ${proc.thread_count} threads running.` : ''),
          fixAvailable: !isProtected,
          fixDescription: isProtected
            ? undefined
            : `End the ${proc.name} process. You can restart it afterward if needed.`,
          fixAction: isProtected ? undefined : {
            type: 'primitive',
            primitive: 'killProcessByName',
            params: { processName: proc.name + '.exe' },
            riskDescription: `This will close ${proc.name}. Any unsaved work in that program will be lost.`
          }
        });
        break; // Only show top offender
      }
    }

    // If no high CPU process found, check processor info
    if (findings.length === 0) {
      const procInfo = results.processor_info;
      if (procInfo?.success && procInfo.data) {
        const cpuData = Array.isArray(procInfo.data) ? procInfo.data[0] : procInfo.data;
        if (cpuData && cpuData.load_percent > 80) {
          findings.push({
            severity: 'warning',
            summary: `Your CPU is running at ${Math.round(cpuData.load_percent)}% overall load`,
            details: 'Multiple processes are contributing to high CPU usage. No single process stands out.',
            fixAvailable: false
          });
        }
      }
    }
  }

  private interpretMemoryFindings(results: Record<string, any>, findings: Finding[]): void {
    const sysMem = results.system_memory;
    if (sysMem?.success && sysMem.data) {
      const mem = Array.isArray(sysMem.data) ? sysMem.data[0] : sysMem.data;
      if (mem && mem.available_mb < 500) {
        findings.push({
          severity: mem.available_mb < 200 ? 'critical' : 'warning',
          summary: `Your system only has ${Math.round(mem.available_mb)} MB of free memory out of ${Math.round(mem.total_mb)} MB`,
          details: `Memory usage is at ${Math.round(mem.percent_used)}%.`,
          fixAvailable: false
        });
      }
    }

    const topMem = results.top_memory_consumers;
    if (topMem?.success && topMem.data) {
      const consumers: any[] = Array.isArray(topMem.data) ? topMem.data : [topMem.data];
      for (const proc of consumers.slice(0, 3)) {
        if (proc.working_set_mb > 1500) {
          const isProtected = ['csrss', 'wininit', 'services', 'lsass', 'svchost', 'dwm', 'explorer', 'system'].includes(proc.name.toLowerCase());
          findings.push({
            severity: proc.working_set_mb > 3000 ? 'critical' : 'warning',
            summary: `${proc.name} is using ${Math.round(proc.working_set_mb)} MB of memory`,
            details: `This is a significant amount of your available RAM.`,
            fixAvailable: !isProtected,
            fixDescription: isProtected ? undefined : `Close ${proc.name} to free up memory. You can restart it afterward.`,
            fixAction: isProtected ? undefined : {
              type: 'primitive',
              primitive: 'killProcessByName',
              params: { processName: proc.name + '.exe' },
              riskDescription: `This will close ${proc.name}. Any unsaved work will be lost.`
            }
          });
          break;
        }
      }
    }
  }

  private interpretDiskFindings(results: Record<string, any>, findings: Finding[]): void {
    const diskUsage = results.disk_usage;
    if (diskUsage?.success && diskUsage.data) {
      const drives: any[] = Array.isArray(diskUsage.data) ? diskUsage.data : [diskUsage.data];
      for (const drive of drives) {
        if (drive.percent_free < 10) {
          findings.push({
            severity: drive.percent_free < 5 ? 'critical' : 'warning',
            summary: `${drive.drive} drive has only ${drive.free_gb.toFixed(1)} GB free (${drive.percent_free.toFixed(0)}% free of ${drive.total_gb.toFixed(0)} GB)`,
            details: 'Low disk space can cause slowdowns, crashes, and prevent saving files.',
            fixAvailable: true,
            fixDescription: 'Clean up temporary files and the Recycle Bin to free up space.',
            fixAction: {
              type: 'primitive',
              primitive: 'cleanTempFiles',
              params: {},
              riskDescription: 'This will delete temporary files and empty the Recycle Bin. No personal files will be affected.'
            }
          });
          break;
        }
      }
    }

    // Check SMART health
    const smart = results.smart_data;
    if (smart?.success && smart.data) {
      const disks: any[] = Array.isArray(smart.data) ? smart.data : [smart.data];
      for (const disk of disks) {
        if (disk.health_status && disk.health_status.toLowerCase() !== 'healthy' && disk.health_status.toLowerCase() !== 'ok') {
          findings.push({
            severity: 'critical',
            summary: `Disk ${disk.drive || disk.model} health status: ${disk.health_status}`,
            details: 'This disk may be failing. Back up your data immediately and contact the helpdesk.',
            fixAvailable: false
          });
        }
      }
    }
  }

  private interpretNetworkFindings(results: Record<string, any>, findings: Finding[]): void {
    // DNS test results
    const dnsTests = results.dns_tests;
    if (dnsTests?.success && dnsTests.data) {
      const tests: any[] = Array.isArray(dnsTests.data) ? dnsTests.data : [dnsTests.data];
      const failedDns = tests.filter((t: any) => !t.resolved);
      if (failedDns.length > 0) {
        findings.push({
          severity: failedDns.length === tests.length ? 'critical' : 'warning',
          summary: `DNS resolution is failing for ${failedDns.map((t: any) => t.host).join(', ')}`,
          details: 'Your computer cannot look up website addresses. This usually prevents all web browsing.',
          fixAvailable: true,
          fixDescription: 'Flush your DNS cache to clear any stale or corrupted entries.',
          fixAction: {
            type: 'primitive',
            primitive: 'flushDNS',
            params: {},
            riskDescription: 'This clears your DNS cache. It\'s completely safe and may briefly slow down your first few website loads.'
          }
        });
        return;
      }
    }

    // Connectivity tests
    const connTests = results.connectivity_tests;
    if (connTests?.success && connTests.data) {
      const tests: any[] = Array.isArray(connTests.data) ? connTests.data : [connTests.data];
      const failedConn = tests.filter((t: any) => !t.reachable);
      if (failedConn.length > 0) {
        findings.push({
          severity: failedConn.length === tests.length ? 'critical' : 'warning',
          summary: `Cannot reach ${failedConn.length} of ${tests.length} test endpoints`,
          details: `Failed to connect to: ${failedConn.map((t: any) => t.endpoint).join(', ')}`,
          fixAvailable: true,
          fixDescription: 'Flush DNS and renew your IP address to restore connectivity.',
          fixAction: {
            type: 'primitive',
            primitive: 'flushDNS',
            params: {},
            riskDescription: 'This flushes DNS cache. It\'s safe and often resolves connectivity issues.'
          }
        });
      }
    }

    // Network adapters
    const adapters = results.network_adapters;
    if (adapters?.success && adapters.data) {
      const adapterList: any[] = Array.isArray(adapters.data) ? adapters.data : [adapters.data];
      const disconnected = adapterList.filter((a: any) => a.status === 'Disconnected' || a.status === 'Down');
      if (disconnected.length > 0 && adapterList.length > 0) {
        findings.push({
          severity: 'info',
          summary: `Network adapter "${disconnected[0].name}" is disconnected`,
          details: 'Check that your cable is plugged in or that Wi-Fi is enabled.',
          fixAvailable: false
        });
      }
    }
  }

  private interpretServiceFindings(results: Record<string, any>, findings: Finding[]): void {
    // Check specific service
    const svcDetail = results.service_details;
    if (svcDetail?.success && svcDetail.data) {
      const svc = Array.isArray(svcDetail.data) ? svcDetail.data[0] : svcDetail.data;
      if (svc && svc.status !== 'Running') {
        findings.push({
          severity: 'warning',
          summary: `${svc.display_name || svc.name} is ${svc.status}`,
          details: `This service should normally be running. Restarting it may fix the issue.`,
          fixAvailable: true,
          fixDescription: `Restart the ${svc.display_name || svc.name} service.`,
          fixAction: {
            type: 'primitive',
            primitive: 'restartService',
            params: { serviceName: svc.name },
            riskDescription: `This will restart the ${svc.display_name || svc.name} service. It may briefly interrupt related functionality.`
          }
        });
        return;
      }
    }

    // Check all failed services
    const failed = results.all_failed_services;
    if (failed?.success && failed.data) {
      const services: any[] = Array.isArray(failed.data) ? failed.data : [failed.data];
      // Show up to 2 most interesting failed services
      for (const svc of services.slice(0, 2)) {
        if (svc.name && svc.display_name) {
          findings.push({
            severity: 'warning',
            summary: `${svc.display_name} service is stopped`,
            details: `This automatic service should be running but isn't.`,
            fixAvailable: true,
            fixDescription: `Restart the ${svc.display_name} service.`,
            fixAction: {
              type: 'primitive',
              primitive: 'restartService',
              params: { serviceName: svc.name },
              riskDescription: `This will restart the ${svc.display_name} service.`
            }
          });
        }
      }
    }
  }

  private interpretGeneralFindings(results: Record<string, any>, findings: Finding[]): void {
    // Check disk usage
    const diskUsage = results.disk_usage;
    if (diskUsage?.success && diskUsage.data) {
      const drives: any[] = Array.isArray(diskUsage.data) ? diskUsage.data : [diskUsage.data];
      for (const drive of drives) {
        if (drive.percent_free < 10) {
          findings.push({
            severity: 'warning',
            summary: `${drive.drive} drive is low on space (${drive.free_gb.toFixed(1)} GB free)`,
            details: 'Low disk space can cause system slowdowns.',
            fixAvailable: true,
            fixDescription: 'Clean up temporary files to free space.',
            fixAction: {
              type: 'primitive',
              primitive: 'cleanTempFiles',
              params: {},
              riskDescription: 'Deletes temporary files only. Personal files are not affected.'
            }
          });
          break;
        }
      }
    }

    // Check failed services
    const failed = results.failed_services;
    if (failed?.success && failed.data) {
      const services: any[] = Array.isArray(failed.data) ? failed.data : [failed.data];
      if (services.length > 0 && services[0].name) {
        findings.push({
          severity: 'warning',
          summary: `${services.length} automatic service${services.length > 1 ? 's are' : ' is'} stopped`,
          details: `Stopped services: ${services.slice(0, 3).map((s: any) => s.display_name || s.name).join(', ')}`,
          fixAvailable: true,
          fixDescription: `Restart the ${services[0].display_name || services[0].name} service.`,
          fixAction: {
            type: 'primitive',
            primitive: 'restartService',
            params: { serviceName: services[0].name },
            riskDescription: `This restarts the service. It may briefly interrupt related functionality.`
          }
        });
      }
    }

    // Check recent errors
    const errors = results.recent_errors;
    if (errors?.success && errors.data) {
      const errList: any[] = Array.isArray(errors.data) ? errors.data : [errors.data];
      if (errList.length > 20) {
        findings.push({
          severity: 'info',
          summary: `${errList.length} errors found in event logs from the last 24 hours`,
          details: 'This is higher than normal. The most frequent sources: ' +
            this.topSources(errList).join(', '),
          fixAvailable: false
        });
      }
    }
  }

  private topSources(errors: any[]): string[] {
    const counts: Map<string, number> = new Map();
    for (const err of errors) {
      const src = err.source || 'Unknown';
      counts.set(src, (counts.get(src) || 0) + 1);
    }
    return Array.from(counts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([src, count]) => `${src} (${count})`);
  }

  private extractServiceHint(session: ConversationSession): string | null {
    const text = (session.userDescription + ' ' + session.followUpAnswers.join(' ')).toLowerCase();

    const serviceMap: Record<string, string> = {
      'printer': 'Spooler',
      'print': 'Spooler',
      'spooler': 'Spooler',
      'windows update': 'wuauserv',
      'update': 'wuauserv',
      'dns': 'Dnscache',
      'audio': 'Audiosrv',
      'bluetooth': 'bthserv',
      'search': 'WSearch',
      'firewall': 'mpssvc',
      'time': 'W32Time'
    };

    for (const [keyword, serviceName] of Object.entries(serviceMap)) {
      if (text.includes(keyword)) {
        return serviceName;
      }
    }

    return null;
  }

  private async executeFix(fix: FixAction): Promise<{ success: boolean; message: string }> {
    try {
      let result: any;

      switch (fix.primitive) {
        case 'killProcessByName':
          result = await this.primitives.killProcessByName(fix.params.processName);
          return {
            success: result.success,
            message: result.success
              ? `Successfully closed ${fix.params.processName}. Your system should feel faster now.`
              : `Could not close ${fix.params.processName}: ${result.error || 'Unknown error'}`
          };

        case 'restartService':
          result = await this.primitives.restartService(fix.params.serviceName);
          return {
            success: result.success,
            message: result.success
              ? `Successfully restarted the ${fix.params.serviceName} service.`
              : `Could not restart ${fix.params.serviceName}: ${result.error || 'Unknown error'}`
          };

        case 'cleanTempFiles':
          result = await this.primitives.cleanTempFiles();
          return {
            success: result.success,
            message: result.success
              ? `Cleaned up temporary files. ${result.output || ''}`
              : `Cleanup partially completed: ${result.error || 'Some files could not be removed'}`
          };

        case 'emptyRecycleBin':
          result = await this.primitives.emptyRecycleBin();
          return {
            success: result.success,
            message: result.success
              ? 'Recycle Bin emptied successfully.'
              : `Could not empty Recycle Bin: ${result.error || 'Unknown error'}`
          };

        case 'flushDNS':
          result = await this.primitives.flushDNS();
          return {
            success: result.success,
            message: result.success
              ? 'DNS cache flushed. Try loading a website again.'
              : `Could not flush DNS: ${result.error || 'Unknown error'}`
          };

        case 'releaseIP':
          result = await this.primitives.releaseIP();
          return { success: result.success, message: result.success ? 'IP released.' : result.error || 'Failed' };

        case 'renewIP':
          result = await this.primitives.renewIP();
          return { success: result.success, message: result.success ? 'IP renewed.' : result.error || 'Failed' };

        default:
          return { success: false, message: `Unknown fix type: ${fix.primitive}` };
      }
    } catch (error: any) {
      return { success: false, message: error.message };
    }
  }

  private createSelfServiceTicket(session: ConversationSession, finding: Finding | null, resolved: boolean): string {
    const description = finding
      ? `Self-service: ${finding.summary}. Fix: ${finding.fixDescription || 'None applied'}`
      : `Self-service: ${session.userDescription}. No fix applied.`;

    const ticketId = this.actionTicketManager.createActionTicket(
      `self-service-${session.id}`,
      'self-service-portal',
      description,
      1
    );

    if (resolved) {
      this.actionTicketManager.markResolved(
        ticketId,
        `Self-service resolution: ${session.fixApplied || 'user-resolved'}`,
        Math.round((Date.now() - session.startedAt) / 1000)
      );
    }

    return ticketId;
  }
}
