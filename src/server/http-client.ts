import axios, { AxiosInstance } from 'axios';
import Logger from '../common/logger';
import { ServerConfig } from './config';

export class HTTPClient {
  private logger: Logger;
  private config: ServerConfig;
  private client: AxiosInstance;
  
  constructor(config: ServerConfig, logger: Logger) {
    this.config = config;
    this.logger = logger;
    
    this.client = axios.create({
      baseURL: config.serverUrl,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
        'X-Agent-ID': config.agentId,
        'X-Client-ID': config.clientId,
        'Authorization': `Bearer ${config.apiKey}`
      }
    });
  }
  
  async registerAgent(): Promise<any> {
    try {
      const response = await this.client.post('/api/agents/register', {
        agent_id: this.config.agentId,
        client_id: this.config.clientId,
        hostname: require('os').hostname(),
        version: '1.0.0',
        capabilities: ['autonomous_remediation', 'playbook_execution']
      });
      
      this.logger.info('Agent registered successfully');
      return response.data;
    } catch (error: any) {
      this.logger.error('Failed to register agent', { error: error.message });
      throw error;
    }
  }
  
  async syncTickets(): Promise<void> {
    try {
      const response = await this.client.get('/api/agents/tickets/pending');
      const pendingTickets = response.data;
      
      this.logger.info(`Synced ${pendingTickets.length} pending tickets from server`);
      
      // TODO: Process pending tickets
    } catch (error: any) {
      this.logger.error('Failed to sync tickets', { error: error.message });
    }
  }
  
  async uploadTicket(ticket: any): Promise<void> {
    try {
      await this.client.post('/api/tickets', ticket);
      this.logger.info('Ticket uploaded to server', { ticket_id: ticket.id });
    } catch (error: any) {
      this.logger.error('Failed to upload ticket', { error: error.message });
    }
  }
  
  async uploadMetrics(metrics: any): Promise<void> {
    try {
      await this.client.post('/api/agents/metrics', {
        agent_id: this.config.agentId,
        timestamp: new Date().toISOString(),
        metrics: metrics
      });
    } catch (error: any) {
      this.logger.error('Failed to upload metrics', { error: error.message });
    }
  }
  
  async getConfig(): Promise<any> {
    try {
      const response = await this.client.get('/api/agents/config');
      this.logger.info('Retrieved agent config from server');
      return response.data;
    } catch (error: any) {
      this.logger.error('Failed to get config', { error: error.message });
      return null;
    }
  }
}
