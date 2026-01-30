import Logger from './core/logger';
import { Database } from './core/database';
import { AgentConfig, loadConfig } from './config/config';
import { SystemMonitor } from './monitoring/system-monitor';
import { RulesEngine } from './detection/rules-engine';
import { Tier1Orchestrator } from './ai/tier1-orchestrator';
import { TicketManager } from './tickets/ticket-manager';
import { PlaybookExecutor } from './execution/playbook-executor';
import { TrainingDataCollector } from './learning/training-collector';
import { ConfidenceAdjuster } from './learning/confidence-adjuster';
import { PatternLearner } from './learning/pattern-learner';
import { WebSocketClient } from './server/websocket-client';
import { HTTPClient } from './server/http-client';
import { DEFAULT_SERVER_CONFIG } from './server/config';

class OPSISAgent {
  private logger: Logger;
  private db: Database;
  private config: AgentConfig;
  private monitor: SystemMonitor;
  private rules: RulesEngine;
  private tier1: Tier1Orchestrator;
  private ticketManager: TicketManager;
  private executor: PlaybookExecutor;
  private trainingCollector: TrainingDataCollector;
  private confidenceAdjuster: ConfidenceAdjuster;
  private patternLearner: PatternLearner;
  private wsClient: WebSocketClient | null = null;
  private httpClient: HTTPClient | null = null;
  
  private monitoringInterval: NodeJS.Timeout | null = null;
  
  constructor() {
    this.logger = new Logger('./logs/agent.log');
    this.db = new Database('./data/agent.db');
    this.config = loadConfig();
    
    this.monitor = new SystemMonitor(this.logger);
    this.rules = new RulesEngine(this.db, this.logger);
    this.tier1 = new Tier1Orchestrator(this.logger);
    this.ticketManager = new TicketManager(this.db, this.logger);
    this.executor = new PlaybookExecutor(this.logger);
    
    this.trainingCollector = new TrainingDataCollector(this.db, this.logger);
    this.confidenceAdjuster = new ConfidenceAdjuster(this.db, this.logger);
    this.patternLearner = new PatternLearner(this.db, this.logger);
    
    if (this.config.server.enabled) {
      const serverConfig = {
        ...DEFAULT_SERVER_CONFIG,
        serverUrl: this.config.server.url,
        websocketUrl: this.config.server.websocketUrl,
        apiKey: this.config.server.apiKey,
        agentId: this.config.agentId,
        clientId: this.config.clientId
      };
      
      this.wsClient = new WebSocketClient(serverConfig, this.logger);
      this.httpClient = new HTTPClient(serverConfig, this.logger);
    }
  }
  
  async start(): Promise<void> {
    this.logger.info(' Starting OPSIS Agent...');
    
    await this.confidenceAdjuster.initialize();
    await this.patternLearner.learnPatterns();
    
    if (this.wsClient && this.httpClient) {
      try {
        await this.httpClient.registerAgent();
        this.wsClient.connect();
      } catch (error) {
        this.logger.warn('Failed to connect to server');
      }
    }
    
    this.startMonitoring();
    this.logger.info(' OPSIS Agent started successfully');
  }
  
  private startMonitoring(): void {
    this.monitoringInterval = setInterval(async () => {
      try {
        const metrics = await this.monitor.collectMetrics();
        
        if (this.wsClient) {
          this.wsClient.sendMetrics(metrics);
        }
        
        const detections = await this.rules.evaluate(metrics);
        
        if (detections.length > 0) {
          this.logger.info(`Detected ${detections.length} issue(s)`, {
            signatures: detections.map((d: any) => d.signature)
          });
          
          for (const detection of detections) {
            await this.handleDetection(detection);
          }
        }
      } catch (error: any) {
        this.logger.error('Monitoring error', { error: error.message });
      }
    }, this.config.monitoring.interval);
  }
  
  private async handleDetection(detection: any): Promise<void> {
    // Check if this issue is in cooldown (already escalated recently)
    if (await this.ticketManager.isInCooldown(detection.signature)) {
      this.logger.info(' Skipping detection - in cooldown period', { 
        signature: detection.signature 
      });
      return;
    }
    const analysis = await this.tier1.analyze(detection);
    const adjustedConfidence = this.confidenceAdjuster.adjustConfidence(
      detection.signature,
      analysis.confidence
    );
    
    analysis.confidence = adjustedConfidence;
    
    const ticket = await this.ticketManager.createTicket({
      signature: detection.signature,
      signature_name: detection.name,
      description: detection.description,
      severity: detection.severity,
      context: detection.context,
      confidence: analysis.confidence,
      recommended_playbooks: analysis.recommended_playbooks,
      escalation_reason: analysis.escalation_reason
    });
    
    this.logger.warn(' ISSUE DETECTED!', {
      ticket_id: ticket.id,
      signature: detection.signature
    });
    
    if (this.wsClient) {
      this.wsClient.sendIssueDetected({
        ticket_id: ticket.id,
        signature: detection.signature,
        confidence: analysis.confidence
      });
    }
    
    const shouldEscalate = this.confidenceAdjuster.shouldEscalate(
      detection.signature,
      detection.risk_class
    );
    
    if (shouldEscalate || analysis.should_escalate || !this.config.execution.enabled) {
      this.logger.warn(' Escalating', { reason: analysis.escalation_reason });
      await this.ticketManager.escalateTicket(ticket.id, analysis.escalation_reason || "Unknown reason");
      
      if (this.wsClient) {
        this.wsClient.sendEscalation(ticket);
      }
    } else {
      await this.executeAutonomously(ticket, analysis, detection);
    }
  }
  
  private async executeAutonomously(ticket: any, analysis: any, detection: any): Promise<void> {
    const playbooks = analysis.recommended_playbooks || [];
    
    if (playbooks.length === 0) {
      await this.ticketManager.escalateTicket(ticket.id, 'No playbooks available');
      return;
    }
    
    for (const playbookId of playbooks) {
      if (!this.executor.getPlaybookInfo(playbookId)) {
        const genericPlaybook = playbookId.replace(/_[A-Z].*$/, '_generic');
        
        if (this.executor.getPlaybookInfo(genericPlaybook)) {
          await this.executePlaybook(ticket, genericPlaybook, detection);
          return;
        }
      } else {
        await this.executePlaybook(ticket, playbookId, detection);
        return;
      }
    }
    
    await this.ticketManager.escalateTicket(ticket.id, 'No viable playbooks');
  }
  
  private async executePlaybook(ticket: any, playbookId: string, detection: any): Promise<void> {
    this.logger.info(' Executing autonomous remediation', { playbook: playbookId });
    
    const startTime = Date.now();
    const params: any = {};
    
    if (detection.context?.service_name) {
      params.serviceName = detection.context.service_name;
    }
    
    if (detection.context?.process_name) {
      params.processName = detection.context.process_name;
    }
    
    const result = await this.executor.executePlaybook(playbookId, params);
    const duration = Date.now() - startTime;
    
    if (result.success) {
      this.logger.info(' Autonomous remediation SUCCESSFUL!', {
        duration_ms: duration,
        steps_completed: result.steps_completed
      });
      
      await this.ticketManager.completeTicket(ticket.id, 'success', duration);
      await this.confidenceAdjuster.recordOutcome(detection.signature, true);
      
      if (this.wsClient) {
        this.wsClient.sendIssueResolved({
          ticket_id: ticket.id,
          result: 'success',
          duration_ms: duration
        });
      }
    } else {
      this.logger.error(' Remediation FAILED', { error: result.error });
      
      await this.ticketManager.completeTicket(ticket.id, 'failed', duration, result.error);
      await this.confidenceAdjuster.recordOutcome(detection.signature, false);
      await this.ticketManager.escalateTicket(ticket.id, `Failed: ${result.error}`);
      
      if (this.wsClient) {
        this.wsClient.sendEscalation(ticket);
      }
    }
  }
  
  stop(): void {
    this.logger.info('Stopping OPSIS Agent...');
    
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
    }
    
    if (this.wsClient) {
      this.wsClient.disconnect();
    }
    
    this.db.close();
    this.logger.info('OPSIS Agent stopped');
  }
}

const agent = new OPSISAgent();
agent.start().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
});

process.on('SIGINT', () => {
  agent.stop();
  process.exit(0);
});

process.on('SIGTERM', () => {
  agent.stop();
  process.exit(0);
});


