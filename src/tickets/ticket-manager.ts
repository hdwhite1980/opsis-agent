import { Database } from '../core/database';
import Logger from '../core/logger';

export interface TicketData {
  signature: string;
  signature_name: string;
  description: string;
  severity: string;
  context: any;
  confidence: number;
  recommended_playbooks: string[];
  escalation_reason?: string;
}

export interface Ticket {
  id: number;
  signature: string;
  signature_name: string;
  description: string;
  severity: string;
  context: string;
  confidence: number;
  recommended_playbooks: string;
  status: string;
  result: string | null;
  duration_ms: number | null;
  error_message: string | null;
  escalated: boolean;
  escalation_reason: string | null;
  created_at: string;
  completed_at: string | null;
  synced: boolean;
}

export class TicketManager {
  private db: Database;
  private logger: Logger;
  
  // Cooldown periods (in minutes)
  private readonly COOLDOWN_PERIODS = {
    1: 5,      // 5 minutes after 1st escalation
    2: 15,     // 15 minutes after 2nd
    3: 30,     // 30 minutes after 3rd
    4: 60,     // 1 hour after 4th
    default: 120  // 2 hours for 5+
  };
  
  constructor(db: Database, logger: Logger) {
    this.db = db;
    this.logger = logger;
  }
  
  async createTicket(data: TicketData): Promise<Ticket> {
    const result = await this.db.run(`
      INSERT INTO local_tickets (
        signature,
        signature_name,
        description,
        severity,
        context,
        confidence,
        recommended_playbooks,
        status,
        escalated,
        escalation_reason,
        created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)
    `, [
      data.signature,
      data.signature_name,
      data.description,
      data.severity,
      JSON.stringify(data.context),
      data.confidence,
      JSON.stringify(data.recommended_playbooks),
      data.escalation_reason ? true : false,
      data.escalation_reason || null,
      new Date().toISOString()
    ]);
    
    const ticket = await this.db.get<Ticket>(
      'SELECT * FROM local_tickets WHERE id = ?',
      [result.lastID]
    );
    
    if (!ticket) {
      throw new Error('Failed to retrieve created ticket');
    }
    
    return ticket;
  }
  
  async isInCooldown(signature: string): Promise<boolean> {
    const cooldown = await this.db.get<any>(
      'SELECT cooldown_until FROM escalation_cooldowns WHERE signature = ?',
      [signature]
    );
    
    if (!cooldown) {
      return false;
    }
    
    const cooldownUntil = new Date(cooldown.cooldown_until);
    const now = new Date();
    
    if (now < cooldownUntil) {
      const minutesLeft = Math.ceil((cooldownUntil.getTime() - now.getTime()) / 60000);
      this.logger.info(`Issue ${signature} is in cooldown`, { minutes_remaining: minutesLeft });
      return true;
    }
    
    // Cooldown expired, remove it
    await this.db.run('DELETE FROM escalation_cooldowns WHERE signature = ?', [signature]);
    return false;
  }
  
  async completeTicket(ticketId: number, result: string, duration: number, error?: string): Promise<void> {
    await this.db.run(`
      UPDATE local_tickets
      SET status = 'completed',
          result = ?,
          duration_ms = ?,
          error_message = ?,
          completed_at = ?
      WHERE id = ?
    `, [result, duration, error || null, new Date().toISOString(), ticketId]);
    
    this.logger.info('Ticket completed', { ticket_id: ticketId, result });
  }
  
  async escalateTicket(ticketId: number, reason: string): Promise<void> {
    // Get the ticket to find its signature
    const ticket = await this.db.get<Ticket>(
      'SELECT * FROM local_tickets WHERE id = ?',
      [ticketId]
    );
    
    if (!ticket) {
      throw new Error(`Ticket ${ticketId} not found`);
    }
    
    // Update ticket
    await this.db.run(`
      UPDATE local_tickets
      SET escalated = 1,
          escalation_reason = ?,
          status = 'escalated'
      WHERE id = ?
    `, [reason, ticketId]);
    
    // Add/update cooldown
    await this.addEscalationCooldown(ticket.signature);
    
    this.logger.warn('Ticket escalated', { ticket_id: ticketId, signature: ticket.signature, reason });
  }
  
  private async addEscalationCooldown(signature: string): Promise<void> {
    const existing = await this.db.get<any>(
      'SELECT escalation_count FROM escalation_cooldowns WHERE signature = ?',
      [signature]
    );
    
    const escalationCount = existing ? existing.escalation_count + 1 : 1;
    
    // Calculate cooldown period
    const cooldownMinutes = this.COOLDOWN_PERIODS[escalationCount as keyof typeof this.COOLDOWN_PERIODS] 
      || this.COOLDOWN_PERIODS.default;
    
    const cooldownUntil = new Date(Date.now() + cooldownMinutes * 60000).toISOString();
    
    if (existing) {
      await this.db.run(`
        UPDATE escalation_cooldowns
        SET last_escalated_at = ?,
            escalation_count = ?,
            cooldown_until = ?
        WHERE signature = ?
      `, [new Date().toISOString(), escalationCount, cooldownUntil, signature]);
    } else {
      await this.db.run(`
        INSERT INTO escalation_cooldowns (signature, last_escalated_at, escalation_count, cooldown_until)
        VALUES (?, ?, ?, ?)
      `, [signature, new Date().toISOString(), escalationCount, cooldownUntil]);
    }
    
    this.logger.info(`Cooldown set for ${signature}`, {
      escalation_count: escalationCount,
      cooldown_minutes: cooldownMinutes,
      cooldown_until: cooldownUntil
    });
  }
  
  async clearCooldown(signature: string): Promise<void> {
    await this.db.run('DELETE FROM escalation_cooldowns WHERE signature = ?', [signature]);
    this.logger.info(`Cooldown cleared for ${signature}`);
  }
  
  async getTicket(ticketId: number): Promise<Ticket | undefined> {
    return await this.db.get<Ticket>(
      'SELECT * FROM local_tickets WHERE id = ?',
      [ticketId]
    );
  }
  
  async getPendingTickets(): Promise<Ticket[]> {
    return await this.db.all<Ticket>(
      'SELECT * FROM local_tickets WHERE status = ? AND synced = 0',
      ['pending']
    );
  }
  
  async getUnsyncedTickets(): Promise<Ticket[]> {
    return await this.db.all<Ticket>(
      'SELECT * FROM local_tickets WHERE synced = 0',
      []
    );
  }
  
  async markSynced(ticketId: number): Promise<void> {
    await this.db.run(
      'UPDATE local_tickets SET synced = 1 WHERE id = ?',
      [ticketId]
    );
  }
}
