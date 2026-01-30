import { Database } from '../core/database';
import Logger from '../core/logger';

export class ConfidenceAdjuster {
  private db: Database;
  private logger: Logger;
  
  // Historical success rates for each signature
  private successRates: Map<string, number> = new Map();
  
  constructor(db: Database, logger: Logger) {
    this.db = db;
    this.logger = logger;
  }
  
  async initialize(): Promise<void> {
    await this.db.ensureInitialized();
    this.logger.info('Initializing confidence adjuster...');
    await this.loadHistoricalSuccessRates();
  }
  
  async loadHistoricalSuccessRates(): Promise<void> {
    // Get success rates for all signatures
    const results = await this.db.all(`
      SELECT 
        signature,
        COUNT(*) as total_attempts,
        SUM(CASE WHEN result = 'success' THEN 1 ELSE 0 END) as successes,
        (SUM(CASE WHEN result = 'success' THEN 1 ELSE 0 END) * 100.0 / COUNT(*)) as success_rate
      FROM local_tickets
      WHERE result IS NOT NULL
      GROUP BY signature
      HAVING COUNT(*) >= 3
    `);
    
    for (const row of results) {
      this.successRates.set(row.signature, row.success_rate);
      this.logger.info(`Loaded success rate for ${row.signature}: ${row.success_rate.toFixed(1)}%`);
    }
  }
  
  adjustConfidence(signature: string, initialConfidence: number): number {
    const historicalRate = this.successRates.get(signature);
    
    if (!historicalRate) {
      // No historical data - use initial confidence
      return initialConfidence;
    }
    
    // Blend initial confidence with historical success rate
    // 70% historical, 30% initial (because history is more reliable)
    const adjusted = (historicalRate * 0.7) + (initialConfidence * 0.3);
    
    this.logger.info(`Adjusted confidence for ${signature}`, {
      initial: initialConfidence,
      historical_rate: historicalRate,
      adjusted: adjusted.toFixed(1)
    });
    
    return adjusted;
  }
  
  async recordOutcome(signature: string, success: boolean): Promise<void> {
    // Update success rate after each execution
    const current = this.successRates.get(signature) || 50;
    
    // Exponential moving average (give recent outcomes more weight)
    const alpha = 0.3; // 30% weight to new data
    const newRate = success 
      ? current + (alpha * (100 - current))
      : current - (alpha * current);
    
    this.successRates.set(signature, newRate);
    
    this.logger.info(`Updated success rate for ${signature}: ${newRate.toFixed(1)}%`);
  }
  
  shouldEscalate(signature: string, riskClass: string): boolean {
    const successRate = this.successRates.get(signature);
    
    // No historical data - be conservative
    if (!successRate) {
      return riskClass !== 'A';
    }
    
    // If success rate is low, escalate even Risk A tasks
    if (successRate < 60) {
      this.logger.warn(`Low success rate for ${signature} (${successRate.toFixed(1)}%) - escalating`);
      return true;
    }
    
    // Risk B: needs high success rate
    if (riskClass === 'B' && successRate < 80) {
      return true;
    }
    
    // Risk C: always escalate
    if (riskClass === 'C') {
      return true;
    }
    
    return false;
  }
}

