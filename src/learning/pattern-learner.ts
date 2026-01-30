import { Database } from '../core/database';
import Logger from '../core/logger';

export interface LearnedPattern {
  pattern_id: string;
  signature: string;
  conditions: {
    cpu_threshold?: number;
    memory_threshold?: number;
    disk_threshold?: number;
    service_stopped?: string;
  };
  recommended_playbooks: string[];
  confidence: number;
  occurrences: number;
}

export class PatternLearner {
  private db: Database;
  private logger: Logger;
  private patterns: Map<string, LearnedPattern> = new Map();
  
  constructor(db: Database, logger: Logger) {
    this.db = db;
    this.logger = logger;
  }
  
  async learnPatterns(): Promise<void> {
    this.logger.info('Learning new patterns from historical data...');
    
    try {
      // Find signatures that have been resolved successfully multiple times
      const successfulSignatures = await this.db.all<any>(`
        SELECT 
          signature,
          COUNT(*) as occurrences,
          AVG(confidence) as avg_confidence,
          recommended_playbooks
        FROM local_tickets
        WHERE result = 'success' AND status = 'completed'
        GROUP BY signature
        HAVING COUNT(*) >= 3
      `);
      
      for (const row of successfulSignatures) {
        const patternId = `LEARNED_${row.signature}`;
        
        // Parse the recommended playbooks (stored as JSON)
        let playbooks: string[] = [];
        try {
          playbooks = JSON.parse(row.recommended_playbooks || '[]');
        } catch {
          playbooks = [];
        }
        
        // Create learned pattern
        const pattern: LearnedPattern = {
          pattern_id: patternId,
          signature: row.signature,
          conditions: {}, // Will be populated from context if needed
          recommended_playbooks: playbooks,
          confidence: Math.round(row.avg_confidence),
          occurrences: row.occurrences
        };
        
        this.patterns.set(patternId, pattern);
        
        this.logger.info(`Learned pattern: ${patternId}`, {
          occurrences: row.occurrences,
          confidence: pattern.confidence,
          playbooks: playbooks.length
        });
      }
      
      this.logger.info(`Pattern learning complete. Learned ${this.patterns.size} patterns`);
      
    } catch (error: any) {
      this.logger.warn('Pattern learning failed', { error: error.message });
    }
  }
  
  async exportPatterns(outputPath: string): Promise<void> {
    const fs = require('fs');
    const patterns = Array.from(this.patterns.values());
    
    fs.writeFileSync(
      outputPath,
      JSON.stringify(patterns, null, 2),
      'utf8'
    );
    
    this.logger.info(`Exported ${patterns.length} patterns to ${outputPath}`);
  }
  
  getPattern(patternId: string): LearnedPattern | undefined {
    return this.patterns.get(patternId);
  }
  
  getAllPatterns(): LearnedPattern[] {
    return Array.from(this.patterns.values());
  }
}
