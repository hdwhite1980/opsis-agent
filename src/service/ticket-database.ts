// ticket-database.ts - Simple In-Memory Ticket Management
// Uses simple JSON file storage instead of SQLite to avoid compilation issues
import * as fs from 'fs';
import * as path from 'path';
import { Logger } from '../common/logger';

export interface Ticket {
  id?: number;
  ticket_id: string;
  timestamp: string;
  type: string;
  description: string;
  status: 'open' | 'in-progress' | 'resolved' | 'failed' | 'pending-review';
  source: 'event-log' | 'manual' | 'monitoring' | 'server-advisory';
  computer_name: string;
  resolved_at?: string;
  resolution_method?: string;
  event_id?: number;
  event_source?: string;
  runbook_id?: string;
  escalated?: number; // 0 or 1
  result?: 'success' | 'failure' | null;
  // Pending action fields
  signature_id?: string;
  runbook_name?: string;
  server_message?: string;
}

export class TicketDatabase {
  private tickets: Ticket[] = [];
  private logger: Logger;
  private dbPath: string;
  private nextId: number = 1;

  constructor(logger: Logger, dbPath: string) {
    this.logger = logger;
    this.dbPath = dbPath;
    
    // Ensure directory exists
    const dir = path.dirname(dbPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    // Load existing tickets
    this.load();
    
    this.logger.info('Ticket database initialized', { path: dbPath, count: this.tickets.length });
  }

  private load(): void {
    try {
      if (fs.existsSync(this.dbPath)) {
        const data = fs.readFileSync(this.dbPath, 'utf8');
        const parsed = JSON.parse(data);
        this.tickets = parsed.tickets || [];
        this.nextId = parsed.nextId || 1;
        this.logger.info('Loaded existing tickets', { count: this.tickets.length });
      } else {
        this.logger.info('No existing ticket database, starting fresh');
      }
    } catch (error) {
      this.logger.error('Error loading tickets', error);
      this.tickets = [];
    }
  }

  private save(): void {
    try {
      const data = JSON.stringify({
        tickets: this.tickets,
        nextId: this.nextId
      }, null, 2);
      const tmpPath = this.dbPath + '.tmp';
      fs.writeFileSync(tmpPath, data, 'utf8');
      fs.renameSync(tmpPath, this.dbPath);
    } catch (error) {
      this.logger.error('Error saving tickets', error);
    }
  }

  public createTicket(ticket: Ticket): string {
    try {
      ticket.id = this.nextId++;
      this.tickets.push(ticket);
      this.save();

      this.logger.info('Ticket created', {
        ticketId: ticket.ticket_id,
        type: ticket.type,
        status: ticket.status
      });

      return ticket.ticket_id;
    } catch (error) {
      this.logger.error('Error creating ticket', error);
      throw error;
    }
  }

  public getTickets(limit: number = 100): Ticket[] {
    try {
      // Sort by timestamp descending and limit
      return this.tickets
        .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
        .slice(0, limit);
    } catch (error) {
      this.logger.error('Error getting tickets', error);
      return [];
    }
  }

  public getTicket(ticketId: string): Ticket | null {
    try {
      return this.tickets.find(t => t.ticket_id === ticketId) || null;
    } catch (error) {
      this.logger.error('Error getting ticket', error);
      return null;
    }
  }

  public updateTicketStatus(
    ticketId: string, 
    status: string, 
    resolution?: string,
    runbookId?: string
  ): void {
    try {
      const ticket = this.tickets.find(t => t.ticket_id === ticketId);
      if (ticket) {
        ticket.status = status as any;
        ticket.resolution_method = resolution || ticket.resolution_method;
        ticket.runbook_id = runbookId || ticket.runbook_id;
        
        if (status === 'resolved' || status === 'failed') {
          ticket.resolved_at = new Date().toISOString();
        }
        
        this.save();

        this.logger.info('Ticket status updated', {
          ticketId,
          status,
          resolution
        });
      }
    } catch (error) {
      this.logger.error('Error updating ticket status', error);
    }
  }

  public closeTicket(
    ticketId: string, 
    resolution: string, 
    result: 'success' | 'failure'
  ): void {
    try {
      const ticket = this.tickets.find(t => t.ticket_id === ticketId);
      if (ticket) {
        ticket.status = 'resolved';
        ticket.resolution_method = resolution;
        ticket.result = result;
        ticket.resolved_at = new Date().toISOString();
        
        this.save();

        this.logger.info('Ticket closed', {
          ticketId,
          resolution,
          result
        });
      }
    } catch (error) {
      this.logger.error('Error closing ticket', error);
    }
  }

  public markAsEscalated(ticketId: string): void {
    try {
      const ticket = this.tickets.find(t => t.ticket_id === ticketId);
      if (ticket) {
        ticket.escalated = 1;
        this.save();

        this.logger.info('Ticket marked as escalated', { ticketId });
      }
    } catch (error) {
      this.logger.error('Error marking ticket as escalated', error);
    }
  }

  public deleteOldTickets(olderThanDays: number = 1): number {
    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - olderThanDays);
      
      const beforeCount = this.tickets.length;
      this.tickets = this.tickets.filter(t => {
        return new Date(t.timestamp) > cutoffDate;
      });
      const deleted = beforeCount - this.tickets.length;
      
      if (deleted > 0) {
        this.save();
      }

      this.logger.info('Old tickets deleted', { count: deleted, olderThanDays });
      return deleted;
    } catch (error) {
      this.logger.error('Error deleting old tickets', error);
      return 0;
    }
  }

  public getStatistics(): {
    totalTickets: number;
    openTickets: number;
    resolvedTickets: number;
    escalatedTickets: number;
    successRate: number;
  } {
    try {
      const total = this.tickets.length;
      const open = this.tickets.filter(t => t.status === 'open').length;
      const resolved = this.tickets.filter(t => t.status === 'resolved').length;
      const escalated = this.tickets.filter(t => t.escalated === 1).length;
      const success = this.tickets.filter(t => t.result === 'success').length;

      const successRate = resolved > 0 ? Math.round((success / resolved) * 100) : 0;

      return {
        totalTickets: total,
        openTickets: open,
        resolvedTickets: resolved,
        escalatedTickets: escalated,
        successRate
      };
    } catch (error) {
      this.logger.error('Error getting statistics', error);
      return {
        totalTickets: 0,
        openTickets: 0,
        resolvedTickets: 0,
        escalatedTickets: 0,
        successRate: 0
      };
    }
  }

  public close(): void {
    this.save();
    this.logger.info('Database closed');
  }
}
