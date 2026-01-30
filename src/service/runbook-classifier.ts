import * as fs from 'fs';
import * as path from 'path';
import { Logger } from '../common/logger';

export type RiskClass = 'A' | 'B' | 'C';

export interface ClassifiedRunbook {
  id: string;
  name: string;
  description: string;
  risk_class: RiskClass;
  auto_execute_threshold: number;
  requires_approval: boolean;
  protected_services: string[];
  triggers: any[];
  steps: any[];
}

export class RunbookClassifier {
  private logger: Logger;
  private runbooksPath: string;
  private classifiedRunbooks: Map<string, ClassifiedRunbook> = new Map();
  
  constructor(logger: Logger, runbooksPath: string) {
    this.logger = logger;
    this.runbooksPath = runbooksPath;
    this.loadAndClassifyRunbooks();
  }
  
  private loadAndClassifyRunbooks(): void {
    try {
      const files = fs.readdirSync(this.runbooksPath);
      const jsonFiles = files.filter(f => f.endsWith('.json'));
      
      for (const file of jsonFiles) {
        const filePath = path.join(this.runbooksPath, file);
        const content = fs.readFileSync(filePath, 'utf-8');
        const runbook = JSON.parse(content);
        
        // Classify if not already classified
        if (!runbook.risk_class) {
          runbook.risk_class = this.classifyRunbook(runbook);
          runbook.auto_execute_threshold = this.getThresholdForClass(runbook.risk_class);
          
          // Save updated runbook
          fs.writeFileSync(filePath, JSON.stringify(runbook, null, 2));
        }
        
        this.classifiedRunbooks.set(runbook.id, runbook);
        this.logger.info('Classified runbook', {
          id: runbook.id,
          name: runbook.name,
          risk_class: runbook.risk_class
        });
      }
      
      this.logger.info('Runbook classification complete', {
        total: this.classifiedRunbooks.size,
        classA: Array.from(this.classifiedRunbooks.values()).filter(r => r.risk_class === 'A').length,
        classB: Array.from(this.classifiedRunbooks.values()).filter(r => r.risk_class === 'B').length,
        classC: Array.from(this.classifiedRunbooks.values()).filter(r => r.risk_class === 'C').length
      });
    } catch (error) {
      this.logger.error('Failed to classify runbooks', error);
    }
  }
  
  private classifyRunbook(runbook: any): RiskClass {
    const steps = runbook.steps || [];
    
    // CLASS C (High Risk - Human Required)
    const highRiskActions = [
      'registry',
      'group_policy',
      'firewall',
      'security_policy',
      'user_account',
      'domain_controller'
    ];
    
    if (steps.some((step: any) => 
      highRiskActions.includes(step.type) ||
      step.action?.includes('Remove-') ||
      step.action?.includes('Disable-') ||
      step.action?.includes('Set-ExecutionPolicy')
    )) {
      return 'C';
    }
    
    // CLASS B (Medium Risk - Approval Token Required)
    const mediumRiskActions = [
      'network_config',
      'system_config',
      'scheduled_task'
    ];
    
    if (steps.some((step: any) =>
      mediumRiskActions.includes(step.type) ||
      step.action?.includes('Restart-Computer') ||
      step.action?.includes('Stop-Computer') ||
      step.requiresApproval === true
    )) {
      return 'B';
    }
    
    // CLASS A (Low Risk - Auto Execute)
    return 'A';
  }
  
  private getThresholdForClass(riskClass: RiskClass): number {
    const thresholds = {
      'A': 85,  // Auto-execute at 85%+ confidence
      'B': 90,  // Need approval token at any confidence
      'C': 95   // Always need human approval
    };
    return thresholds[riskClass];
  }
  
  getRunbook(runbookId: string): ClassifiedRunbook | null {
    return this.classifiedRunbooks.get(runbookId) || null;
  }

  getRunbookClass(runbookId: string): RiskClass | null {
    const runbook = this.classifiedRunbooks.get(runbookId);
    return runbook?.risk_class || null;
  }
  
  canAutoExecute(runbookId: string, confidence: number): boolean {
    const runbook = this.classifiedRunbooks.get(runbookId);
    if (!runbook) return false;
    
    if (runbook.risk_class === 'C') return false; // Never auto-execute Class C
    if (runbook.risk_class === 'B') return false; // Class B needs approval token
    
    return confidence >= runbook.auto_execute_threshold; // Class A can auto-execute
  }
  
  requiresApproval(runbookId: string): boolean {
    const runbook = this.classifiedRunbooks.get(runbookId);
    return runbook?.risk_class === 'B' || runbook?.risk_class === 'C';
  }
}
