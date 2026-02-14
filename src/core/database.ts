import sqlite3 from 'sqlite3';
import Logger from './logger';

export class Database {
  private db: sqlite3.Database;
  private logger: Logger;
  private initialized: Promise<void>;
  
  constructor(dbPath: string) {
    this.db = new sqlite3.Database(dbPath);
    this.logger = new Logger('./logs/agent.log');
    this.initialized = this.initialize();
  }
  
  private async initialize(): Promise<void> {
    // Wait for all tables to be created
    await this.run(`
      CREATE TABLE IF NOT EXISTS baseline_samples (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cpu REAL,
        memory REAL,
        disk TEXT,
        processes TEXT,
        services TEXT,
        timestamp TEXT
      )
    `);
    
    await this.run(`
      CREATE TABLE IF NOT EXISTS local_tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        signature TEXT NOT NULL,
        signature_name TEXT,
        description TEXT,
        severity TEXT,
        context TEXT,
        confidence REAL,
        recommended_playbooks TEXT,
        status TEXT DEFAULT 'pending',
        result TEXT,
        duration_ms INTEGER,
        error_message TEXT,
        escalated INTEGER DEFAULT 0,
        escalation_reason TEXT,
        created_at TEXT,
        completed_at TEXT,
        synced INTEGER DEFAULT 0
      )
    `);
    
    await this.run(`
      CREATE TABLE IF NOT EXISTS historical_success_rates (
        signature TEXT PRIMARY KEY,
        total_attempts INTEGER DEFAULT 0,
        successful_attempts INTEGER DEFAULT 0,
        failed_attempts INTEGER DEFAULT 0,
        success_rate REAL DEFAULT 0,
        last_updated TEXT
      )
    `);
    
    await this.run(`CREATE INDEX IF NOT EXISTS idx_tickets_signature ON local_tickets(signature)`);
    await this.run(`CREATE INDEX IF NOT EXISTS idx_tickets_status ON local_tickets(status)`);
    await this.run(`CREATE INDEX IF NOT EXISTS idx_tickets_created ON local_tickets(created_at)`);

    await this.run(`
      CREATE TABLE IF NOT EXISTS behavioral_profiles (
        metric_key TEXT NOT NULL,
        hour_of_day INTEGER NOT NULL,
        is_weekday INTEGER NOT NULL,
        sample_count INTEGER DEFAULT 0,
        mean REAL DEFAULT 0,
        m2 REAL DEFAULT 0,
        min_value REAL,
        max_value REAL,
        last_updated TEXT,
        PRIMARY KEY (metric_key, hour_of_day, is_weekday)
      )
    `);

    await this.run(`CREATE INDEX IF NOT EXISTS idx_profiles_metric ON behavioral_profiles(metric_key)`);

    await this.run(`
      CREATE TABLE IF NOT EXISTS process_frequency (
        process_name TEXT PRIMARY KEY,
        occurrence_count INTEGER DEFAULT 0,
        last_seen TEXT
      )
    `);

    this.logger.info('Database initialized');
  }
  
  async ensureInitialized(): Promise<void> {
    await this.initialized;
  }
  
  async run(sql: string, params: any[] = []): Promise<{ lastID: number; changes: number }> {
    return new Promise((resolve, reject) => {
      this.db.run(sql, params, function(err) {
        if (err) reject(err);
        else resolve({ lastID: this.lastID, changes: this.changes });
      });
    });
  }
  
  async get<T = any>(sql: string, params: any[] = []): Promise<T | undefined> {
    await this.ensureInitialized();
    return new Promise((resolve, reject) => {
      this.db.get(sql, params, (err, row) => {
        if (err) reject(err);
        else resolve(row as T | undefined);
      });
    });
  }
  
  async all<T = any>(sql: string, params: any[] = []): Promise<T[]> {
    await this.ensureInitialized();
    return new Promise((resolve, reject) => {
      this.db.all(sql, params, (err, rows) => {
        if (err) reject(err);
        else resolve(rows as T[]);
      });
    });
  }
  
  close(): void {
    this.db.close();
  }
}

