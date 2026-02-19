// ticket-database.ts - Simple In-Memory Ticket Management
// Uses simple JSON file storage instead of SQLite to avoid compilation issues
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { Logger } from '../common/logger';
import { z, TicketSchema, atomicWriteFileSync } from '../security';

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
  // Diagnostic and resolution detail fields
  diagnostic_summary?: string;
  recommended_action?: string;
  resolution_category?: 'fixed' | 'ignored' | 'protected' | 'escalated' | 'pending';
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
        // Security: Check for symlink attack
        const stats = fs.lstatSync(this.dbPath);
        if (stats.isSymbolicLink()) {
          this.logger.error('Security: Ticket database path is a symlink, refusing to load');
          this.tickets = [];
          return;
        }

        const data = fs.readFileSync(this.dbPath, 'utf8');
        const parsed = JSON.parse(data);

        // Validate loaded data structure
        if (!parsed || typeof parsed !== 'object') {
          throw new Error('Invalid database format');
        }

        // Validate tickets array
        if (!Array.isArray(parsed.tickets)) {
          throw new Error('Invalid tickets array');
        }

        // Validate each ticket has required fields
        const validTickets: Ticket[] = [];
        for (const ticket of parsed.tickets) {
          if (ticket && typeof ticket === 'object' &&
              typeof ticket.ticket_id === 'string' &&
              typeof ticket.timestamp === 'string' &&
              typeof ticket.type === 'string' &&
              typeof ticket.description === 'string' &&
              typeof ticket.status === 'string') {
            validTickets.push(ticket as Ticket);
          } else {
            this.logger.warn('Skipping invalid ticket during load', { ticket_id: ticket?.ticket_id });
          }
        }

        this.tickets = validTickets;
        this.nextId = typeof parsed.nextId === 'number' && parsed.nextId > 0 ? parsed.nextId : 1;
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

      // Use atomic write with restricted permissions
      atomicWriteFileSync(this.dbPath, data, 0o600);
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

  public findOpenTicketByEvent(eventId: number, eventSource: string): Ticket | null {
    return this.tickets.find(t =>
      (t.status === 'open' || t.status === 'in-progress') &&
      t.event_id === eventId &&
      t.event_source === eventSource &&
      t.source === 'event-log'
    ) || null;
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
    result: 'success' | 'failure',
    resolutionCategory?: 'fixed' | 'ignored' | 'protected' | 'escalated' | 'pending'
  ): void {
    try {
      const ticket = this.tickets.find(t => t.ticket_id === ticketId);
      if (ticket) {
        ticket.status = 'resolved';
        ticket.resolution_method = resolution;
        ticket.result = result;
        ticket.resolved_at = new Date().toISOString();
        if (resolutionCategory) {
          ticket.resolution_category = resolutionCategory;
        }
        
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

  public deleteAllTickets(): number {
    try {
      const count = this.tickets.length;
      this.tickets = [];
      this.nextId = 1;
      this.save();
      this.logger.info('All tickets deleted', { count });
      return count;
    } catch (error) {
      this.logger.error('Error deleting all tickets', error);
      return 0;
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
    autoResolved: number;
    awaitingReview: number;
    remediationAttempted: number;
    fixRate: number;
  } {
    try {
      const total = this.tickets.length;
      const open = this.tickets.filter(t => t.status === 'open').length;
      const resolved = this.tickets.filter(t => t.status === 'resolved').length;
      const escalated = this.tickets.filter(t => t.escalated === 1).length;
      const success = this.tickets.filter(t => t.result === 'success').length;
      const failed = this.tickets.filter(t => t.result === 'failure').length;

      // Auto-resolved: tickets where a runbook ran and succeeded
      const autoResolved = success;

      // Awaiting review: escalated tickets still in open status
      const awaitingReview = this.tickets.filter(t => t.escalated === 1 && t.status === 'open').length;

      // Fix rate: success out of all remediation attempts (success + failure)
      // Only counts tickets where a runbook was actually tried
      const attempted = success + failed;
      const fixRate = attempted > 0 ? Math.round((success / attempted) * 100) : 0;

      return {
        totalTickets: total,
        openTickets: open,
        resolvedTickets: resolved,
        escalatedTickets: escalated,
        autoResolved,
        awaitingReview,
        remediationAttempted: attempted,
        fixRate
      };
    } catch (error) {
      this.logger.error('Error getting statistics', error);
      return {
        totalTickets: 0,
        openTickets: 0,
        resolvedTickets: 0,
        escalatedTickets: 0,
        autoResolved: 0,
        awaitingReview: 0,
        remediationAttempted: 0,
        fixRate: 0
      };
    }
  }

  public close(): void {
    this.save();
    this.logger.info('Database closed');
  }
}
