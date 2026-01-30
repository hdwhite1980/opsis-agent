import { Logger } from '../common/logger';
import { TicketDatabase, Ticket } from './ticket-database';
import * as os from 'os';

export type ActionStatus = 'open' | 'in-progress' | 'resolved' | 'failed' | 'closed';

export interface ActionTicket extends Ticket {
  action_type: 'AUTO_REMEDIATION' | 'MANUAL_ACTION' | 'ESCALATION';
  playbook_id?: string;
  signature_id?: string;
  steps_completed?: number;
  steps_total?: number;
  error_message?: string;
  resolution_time_seconds?: number;
}

export class ActionTicketManager {
  private logger: Logger;
  private ticketDb: TicketDatabase;
  
  constructor(logger: Logger, ticketDb: TicketDatabase) {
    this.logger = logger;
    this.ticketDb = ticketDb;
  }
  
  /**
   * Create an action ticket when starting remediation
   */
  createActionTicket(
    signatureId: string,
    playbookId: string,
    description: string,
    totalSteps: number
  ): string {
    const ticketId = `action-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    const ticket: ActionTicket = {
      ticket_id: ticketId,
      timestamp: new Date().toISOString(),
      type: 'auto-remediation',
      description: description,
      status: 'open',
      source: 'monitoring',  // Changed from 'agent' to 'monitoring'
      computer_name: os.hostname(),
      escalated: 0,
      action_type: 'AUTO_REMEDIATION',
      playbook_id: playbookId,
      signature_id: signatureId,
      steps_completed: 0,
      steps_total: totalSteps
    };
    
    this.ticketDb.createTicket(ticket);
    
    this.logger.info('Action ticket created', {
      ticketId,
      playbookId,
      signatureId
    });
    
    return ticketId;
  }
  
  /**
   * Update ticket to IN_PROGRESS when execution starts
   */
  markInProgress(ticketId: string, playbookId: string): void {
    this.ticketDb.updateTicketStatus(ticketId, 'in-progress', undefined, playbookId);
    
    this.logger.info('Action ticket in progress', { ticketId, playbookId });
  }
  
  /**
   * Update step completion
   */
  updateStepProgress(ticketId: string, stepsCompleted: number): void {
    const ticket = this.ticketDb.getTicket(ticketId);
    if (ticket) {
      // Update the ticket object
      (ticket as ActionTicket).steps_completed = stepsCompleted;
      // Save changes by updating status (triggers save)
      this.ticketDb.updateTicketStatus(ticketId, ticket.status);
    }
  }
  
  /**
   * Mark ticket as RESOLVED on success
   */
  markResolved(
    ticketId: string,
    resolution: string,
    executionTimeSeconds: number
  ): void {
    const ticket = this.ticketDb.getTicket(ticketId);
    if (ticket) {
      (ticket as ActionTicket).resolution_time_seconds = executionTimeSeconds;
    }
    
    this.ticketDb.updateTicketStatus(ticketId, 'resolved', resolution);
    
    // Auto-close after 5 seconds
    setTimeout(() => {
      const currentTicket = this.ticketDb.getTicket(ticketId);
      if (currentTicket) {
        // Manually set status to closed since it's not in the type union
        (currentTicket as any).status = 'closed';
        this.ticketDb.updateTicketStatus(ticketId, 'resolved', 'Auto-closed after successful resolution');
        this.logger.info('Action ticket auto-closed', { ticketId });
      }
    }, 5000);
    
    this.logger.info('Action ticket resolved', {
      ticketId,
      executionTimeSeconds
    });
  }
  
  /**
   * Mark ticket as FAILED and create escalation
   */
  markFailed(
    ticketId: string,
    errorMessage: string,
    createEscalation: boolean = true
  ): string | null {
    const ticket = this.ticketDb.getTicket(ticketId);
    if (ticket) {
      (ticket as ActionTicket).error_message = errorMessage;
      this.ticketDb.updateTicketStatus(ticketId, 'failed');
    }
    
    this.logger.error('Action ticket failed', {
      ticketId,
      error: errorMessage
    });
    
    if (createEscalation) {
      return this.createEscalationTicket(ticket as ActionTicket, errorMessage);
    }
    
    return null;
  }
  
  /**
   * Create an escalation ticket for human attention
   */
  private createEscalationTicket(
    originalTicket: ActionTicket,
    reason: string
  ): string {
    const escalationId = `escalation-${Date.now()}`;
    
    const escalationTicket: ActionTicket = {
      ticket_id: escalationId,
      timestamp: new Date().toISOString(),
      type: 'escalation',
      description: `[ESCALATED] ${reason}\n\nOriginal: ${originalTicket.description}`,
      status: 'open',
      source: 'monitoring',  // Changed from 'agent-escalation' to 'monitoring'
      computer_name: os.hostname(),
      escalated: 1,
      action_type: 'ESCALATION',
      playbook_id: originalTicket.playbook_id,
      signature_id: originalTicket.signature_id,
      error_message: reason
    };
    
    this.ticketDb.createTicket(escalationTicket);
    this.ticketDb.markAsEscalated(escalationId);
    
    this.logger.warn('Escalation ticket created', {
      escalationId,
      originalTicket: originalTicket.ticket_id
    });
    
    return escalationId;
  }
  
  /**
   * Get ticket status
   */
  getTicketStatus(ticketId: string): ActionStatus | null {
    const ticket = this.ticketDb.getTicket(ticketId);
    return ticket?.status as ActionStatus || null;
  }
}
