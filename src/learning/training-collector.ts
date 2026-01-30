import { Database } from '../core/database';
import Logger from '../core/logger';

export interface TrainingExample {
  // Input features
  cpu_avg: number;
  memory_avg: number;
  disk_avg: number;
  disk_free_gb: number;
  process_count: number;
  service_stopped_count: number;
  
  // Context
  signature: string;
  playbook_id: string;
  
  // Outcome
  result: 'success' | 'failed' | 'escalated';
  duration_ms: number;
  confidence: number;
  
  // Metadata
  timestamp: string;
}

export class TrainingDataCollector {
  private db: Database;
  private logger: Logger;
  
  constructor(db: Database, logger: Logger) {
    this.db = db;
    this.logger = logger;
  }
  
  async collectTrainingData(): Promise<TrainingExample[]> {
    // Get all completed tickets with outcomes
    const tickets = await this.db.all(`
      SELECT * FROM local_tickets
      WHERE result IS NOT NULL
      ORDER BY created_at DESC
    `);
    
    const examples: TrainingExample[] = [];
    
    for (const ticket of tickets) {
      try {
        const context = JSON.parse(ticket.context || '{}');
        
        examples.push({
          // Features from baseline
          cpu_avg: context.baseline?.cpu_avg || 0,
          memory_avg: context.baseline?.memory_avg || 0,
          disk_avg: context.baseline?.disk_avg || 0,
          disk_free_gb: context.current?.disk_free_gb || 0,
          process_count: context.current?.process_count || 0,
          service_stopped_count: context.current?.service_stopped_count || 0,
          
          // Classification
          signature: ticket.signature,
          playbook_id: ticket.playbook_id,
          
          // Outcome
          result: ticket.result,
          duration_ms: ticket.duration_ms || 0,
          confidence: ticket.confidence || 0,
          
          timestamp: ticket.created_at
        });
      } catch (error) {
        this.logger.warn('Failed to parse ticket context', { ticket_id: ticket.id });
      }
    }
    
    return examples;
  }
  
  async saveTrainingDataset(outputPath: string): Promise<void> {
    const examples = await this.collectTrainingData();
    
    this.logger.info(`Collected ${examples.length} training examples`);
    
    // Convert to CSV format
    const csv = this.convertToCSV(examples);
    
    const fs = require('fs');
    fs.writeFileSync(outputPath, csv, 'utf-8');
    
    this.logger.info(`Training dataset saved to ${outputPath}`);
  }
  
  private convertToCSV(examples: TrainingExample[]): string {
    if (examples.length === 0) return '';
    
    // Header
    const headers = Object.keys(examples[0]).join(',');
    
    // Rows
    const rows = examples.map(ex => 
      Object.values(ex).map(v => 
        typeof v === 'string' ? `"${v}"` : v
      ).join(',')
    );
    
    return [headers, ...rows].join('\n');
  }
  
  async getSuccessRate(signature: string): Promise<number> {
    const results = await this.db.all(`
      SELECT 
        COUNT(*) as total,
        SUM(CASE WHEN result = 'success' THEN 1 ELSE 0 END) as success_count
      FROM local_tickets
      WHERE signature = ?
    `, [signature]);
    
    const { total, success_count } = results[0];
    
    if (total === 0) return 0;
    return (success_count / total) * 100;
  }
  
  async getAverageDuration(playbookId: string): Promise<number> {
    const results = await this.db.all(`
      SELECT AVG(duration_ms) as avg_duration
      FROM local_tickets
      WHERE playbook_id = ?
      AND result = 'success'
    `, [playbookId]);
    
    return results[0]?.avg_duration || 0;
  }
}
