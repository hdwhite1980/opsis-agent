import { SystemMetrics, Tier1Result } from '../types';
import { ExpertRulesEngine, RuleResult } from './expert-rules';
import Logger from '../core/logger';
import crypto from 'crypto';

export class Tier1Orchestrator {
  private rulesEngine: ExpertRulesEngine;
  private logger: Logger;
  private confidenceThreshold: number;
  private escalationThreshold: number;
  
  constructor(logger: Logger, confidenceThreshold: number = 85, escalationThreshold: number = 85) {
    this.rulesEngine = new ExpertRulesEngine(logger);
    this.logger = logger;
    this.confidenceThreshold = confidenceThreshold;
    this.escalationThreshold = escalationThreshold;
  }
  
  async analyze(metrics: SystemMetrics): Promise<Tier1Result | null> {
    // Step 1: Run expert rules
    const ruleResults = this.rulesEngine.evaluateRules(metrics);
    
    if (ruleResults.length === 0) {
      // No issues detected
      return null;
    }
    
    // Step 2: Get best match
    const bestMatch = this.rulesEngine.getBestMatch(ruleResults);
    
    if (!bestMatch) {
      return null;
    }
    
    // Step 3: Determine if we should escalate
    const shouldEscalate = this.shouldEscalate(bestMatch);
    
    // Step 4: Build Tier 1 result
    const result: Tier1Result = {
      source: 'rule',
      signature_id: bestMatch.signature_id,
      signature_name: bestMatch.signature_name,
      confidence: bestMatch.confidence,
      is_issue: true,
      should_escalate: shouldEscalate,
      candidate_playbooks: bestMatch.candidate_playbooks?.map((pb, index) => ({
        playbook_id: pb,
        rank: index + 1,
        score: 100 - (index * 10)
      })) || [],
      risk_class: bestMatch.risk_class
    };
    
    this.logger.info('Tier 1 analysis complete', {
      signature: result.signature_id,
      confidence: result.confidence,
      should_escalate: result.should_escalate,
      playbooks: result.candidate_playbooks.length
    });
    
    return result;
  }
  
  private shouldEscalate(result: RuleResult): boolean {
    // Escalate if:
    // 1. Confidence below threshold
    if (result.confidence < this.escalationThreshold) {
      return true;
    }
    
    // 2. Risk class B or C (requires approval)
    if (result.risk_class === 'B' || result.risk_class === 'C') {
      return true;
    }
    
    // 3. No candidate playbooks
    if (!result.candidate_playbooks || result.candidate_playbooks.length === 0) {
      return true;
    }
    
    // 4. Critical severity always escalate for human awareness
    if (result.severity === 'critical') {
      return true;
    }
    
    return false;
  }
}
