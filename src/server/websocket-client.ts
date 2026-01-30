import WebSocket from 'ws';
import Logger from '../core/logger';
import { ServerConfig } from './config';

export interface AgentMessage {
  type: 'heartbeat' | 'metrics' | 'issue_detected' | 'issue_resolved' | 'escalation';
  timestamp: string;
  data: any;
}

export class WebSocketClient {
  private logger: Logger;
  private config: ServerConfig;
  private ws: WebSocket | null = null;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private heartbeatTimer: NodeJS.Timeout | null = null;
  private isConnected: boolean = false;
  
  constructor(config: ServerConfig, logger: Logger) {
    this.config = config;
    this.logger = logger;
  }
  
  connect(): void {
    if (this.isConnected) {
      this.logger.warn('WebSocket already connected');
      return;
    }
    
    this.logger.info('Connecting to server...', { url: this.config.websocketUrl });
    
    this.ws = new WebSocket(this.config.websocketUrl, {
      headers: {
        'X-Agent-ID': this.config.agentId,
        'X-Client-ID': this.config.clientId,
        'Authorization': `Bearer ${this.config.apiKey}`
      }
    });
    
    this.ws.on('open', () => {
      this.logger.info(' Connected to server');
      this.isConnected = true;
      
      // Send initial registration
      this.send({
        type: 'heartbeat',
        timestamp: new Date().toISOString(),
        data: {
          status: 'online',
          version: '1.0.0'
        }
      });
      
      // Start heartbeat
      this.startHeartbeat();
    });
    
    this.ws.on('message', (data: WebSocket.Data) => {
      try {
        const message = JSON.parse(data.toString());
        this.handleMessage(message);
      } catch (error: any) {
        this.logger.error('Failed to parse server message', { error: error.message });
      }
    });
    
    this.ws.on('close', () => {
      this.logger.warn('Disconnected from server');
      this.isConnected = false;
      this.stopHeartbeat();
      this.scheduleReconnect();
    });
    
    this.ws.on('error', (error: Error) => {
      this.logger.error('WebSocket error', { error: error.message });
    });
  }
  
  disconnect(): void {
    this.logger.info('Disconnecting from server...');
    
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    
    this.stopHeartbeat();
    
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    
    this.isConnected = false;
  }
  
  send(message: AgentMessage): void {
    if (!this.isConnected || !this.ws) {
      this.logger.warn('Cannot send message - not connected');
      return;
    }
    
    try {
      this.ws.send(JSON.stringify(message));
    } catch (error: any) {
      this.logger.error('Failed to send message', { error: error.message });
    }
  }
  
  sendMetrics(metrics: any): void {
    this.send({
      type: 'metrics',
      timestamp: new Date().toISOString(),
      data: metrics
    });
  }
  
  sendIssueDetected(issue: any): void {
    this.send({
      type: 'issue_detected',
      timestamp: new Date().toISOString(),
      data: issue
    });
  }
  
  sendIssueResolved(ticket: any): void {
    this.send({
      type: 'issue_resolved',
      timestamp: new Date().toISOString(),
      data: ticket
    });
  }
  
  sendEscalation(ticket: any): void {
    this.send({
      type: 'escalation',
      timestamp: new Date().toISOString(),
      data: ticket
    });
  }
  
  private handleMessage(message: any): void {
    this.logger.info('Received server message', { type: message.type });
    
    switch (message.type) {
      case 'execute_playbook':
        // Server requested playbook execution
        this.logger.info('Server requested playbook execution', { 
          playbook: message.data.playbook_id 
        });
        // TODO: Execute playbook and send result
        break;
      
      case 'update_config':
        // Server sent config update
        this.logger.info('Received config update from server');
        // TODO: Update agent configuration
        break;
      
      case 'pong':
        // Heartbeat response
        break;
      
      default:
        this.logger.warn('Unknown message type', { type: message.type });
    }
  }
  
  private startHeartbeat(): void {
    this.heartbeatTimer = setInterval(() => {
      this.send({
        type: 'heartbeat',
        timestamp: new Date().toISOString(),
        data: { status: 'online' }
      });
    }, this.config.heartbeatInterval);
  }
  
  private stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }
  
  private scheduleReconnect(): void {
    if (this.reconnectTimer) return;
    
    this.logger.info(`Reconnecting in ${this.config.reconnectInterval / 1000} seconds...`);
    
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, this.config.reconnectInterval);
  }
}
