import WebSocket from 'ws';
import * as https from 'https';
import * as tls from 'tls';
import Logger from '../core/logger';
import { ServerConfig } from './config';
import {
  signMessage,
  verifySignature,
  WSMessageTypes,
  verifyCertificateFingerprint,
  setTrustedCertificates,
  tryParseJSON
} from '../security';

export interface AgentMessage {
  type: 'heartbeat' | 'metrics' | 'issue_detected' | 'issue_resolved' | 'escalation' | 'register' | 'telemetry';
  timestamp: string;
  data: any;
  signature?: string;
  nonce?: string;
}

interface ServerMessage {
  type: string;
  data?: any;
  signature?: string;
  nonce?: string;
  timestamp?: string;
}

// Rate limiting for incoming messages
interface RateLimitState {
  count: number;
  resetTime: number;
}

const MAX_MESSAGES_PER_MINUTE = 200;
const MAX_MESSAGE_SIZE = 1048576; // 1MB
const ALLOWED_SERVER_MESSAGE_TYPES = new Set(WSMessageTypes);

export class WebSocketClient {
  private logger: Logger;
  private config: ServerConfig;
  private ws: WebSocket | null = null;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private heartbeatTimer: NodeJS.Timeout | null = null;
  private isConnected: boolean = false;
  private serverSecret: string = '';
  private rateLimit: RateLimitState = { count: 0, resetTime: 0 };
  private messageHandlers: Map<string, (data: any) => void> = new Map();

  constructor(config: ServerConfig, logger: Logger) {
    this.config = config;
    this.logger = logger;

    // Set up certificate pinning if configured
    if (config.trustedCertFingerprints) {
      setTrustedCertificates(config.trustedCertFingerprints);
    }
  }

  connect(): void {
    if (this.isConnected) {
      this.logger.warn('WebSocket already connected');
      return;
    }

    // Validate URL uses secure WebSocket
    if (!this.config.websocketUrl.startsWith('wss://')) {
      this.logger.error('Security: WebSocket URL must use wss:// protocol');
      return;
    }

    this.logger.info('Connecting to server...', { url: this.sanitizeUrl(this.config.websocketUrl) });

    try {
      // Create WebSocket with TLS options
      this.ws = new WebSocket(this.config.websocketUrl, {
        headers: {
          'X-Agent-ID': this.config.agentId,
          'X-Client-ID': this.config.clientId,
          'Authorization': `Bearer ${this.config.apiKey}`
        },
        // TLS options for certificate verification
        rejectUnauthorized: true,
        checkServerIdentity: (hostname: string, cert: tls.PeerCertificate) => {
          // Verify certificate fingerprint if pinning is enabled
          if (!verifyCertificateFingerprint(cert)) {
            return new Error('Certificate fingerprint mismatch');
          }
          // Default hostname verification
          return tls.checkServerIdentity(hostname, cert);
        }
      });

      this.ws.on('open', () => {
        this.logger.info('Connected to server');
        this.isConnected = true;

        // Send initial registration with signature
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
        this.handleIncomingMessage(data);
      });

      this.ws.on('close', (code: number) => {
        this.logger.warn('Disconnected from server', { code });
        this.isConnected = false;
        this.stopHeartbeat();
        this.scheduleReconnect();
      });

      this.ws.on('error', (error: Error) => {
        this.logger.error('WebSocket error', { error: error.message });
      });

    } catch (error: any) {
      this.logger.error('Failed to create WebSocket connection', { error: error.message });
      this.scheduleReconnect();
    }
  }

  disconnect(): void {
    this.logger.info('Disconnecting from server...');

    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    this.stopHeartbeat();

    if (this.ws) {
      this.ws.close(1000, 'Client disconnecting');
      this.ws = null;
    }

    this.isConnected = false;
  }

  private handleIncomingMessage(data: WebSocket.Data): void {
    try {
      // Check message size
      const messageStr = data.toString();
      if (messageStr.length > MAX_MESSAGE_SIZE) {
        this.logger.warn('Message too large, ignoring', { size: messageStr.length });
        return;
      }

      // Rate limiting
      if (!this.checkRateLimit()) {
        this.logger.warn('Rate limit exceeded for incoming messages');
        return;
      }

      // SECURITY: Use safe JSON parsing
      const { parsed, error: parseError } = tryParseJSON(messageStr);
      if (parseError || !parsed) {
        this.logger.warn('Invalid JSON in server message', { error: parseError });
        return;
      }
      const message = parsed as ServerMessage;

      // Validate message structure
      if (!message || typeof message !== 'object' || typeof message.type !== 'string') {
        this.logger.warn('Invalid message structure');
        return;
      }

      // Validate message type is allowed
      if (!ALLOWED_SERVER_MESSAGE_TYPES.has(message.type as any)) {
        this.logger.warn('Unknown server message type', { type: message.type });
        return;
      }

      // Verify signature if present and server secret is configured
      if (this.serverSecret && message.signature && message.nonce && message.timestamp) {
        const verification = verifySignature(
          { type: message.type, data: message.data },
          message.signature,
          message.nonce,
          message.timestamp,
          this.serverSecret
        );

        if (!verification.valid) {
          this.logger.warn('Invalid server message signature', { error: verification.error });
          return;
        }
      }

      // Handle the message
      this.handleMessage(message);

    } catch (error: any) {
      this.logger.error('Failed to process server message', { error: error.message });
    }
  }

  private checkRateLimit(): boolean {
    const now = Date.now();

    if (now > this.rateLimit.resetTime) {
      this.rateLimit = { count: 0, resetTime: now + 60000 };
    }

    this.rateLimit.count++;
    return this.rateLimit.count <= MAX_MESSAGES_PER_MINUTE;
  }

  send(message: AgentMessage): void {
    if (!this.isConnected || !this.ws) {
      this.logger.warn('Cannot send message - not connected');
      return;
    }

    try {
      // Sign outgoing messages if server secret is configured
      if (this.serverSecret) {
        const { signature, nonce, timestamp } = signMessage(
          { type: message.type, data: message.data },
          this.serverSecret
        );
        message.signature = signature;
        message.nonce = nonce;
        message.timestamp = timestamp;
      }

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

  // Register custom message handler
  onServerMessage(type: string, handler: (data: any) => void): void {
    this.messageHandlers.set(type, handler);
  }

  // Set server secret for message signing/verification
  setServerSecret(secret: string): void {
    this.serverSecret = secret;
  }

  private handleMessage(message: ServerMessage): void {
    this.logger.info('Received server message', { type: message.type });

    // Check for custom handler first
    const customHandler = this.messageHandlers.get(message.type);
    if (customHandler) {
      try {
        customHandler(message.data);
      } catch (error: any) {
        this.logger.error('Custom message handler error', { type: message.type, error: error.message });
      }
      return;
    }

    // Default handlers
    switch (message.type) {
      case 'welcome':
        // Server sent welcome message, may include server secret
        if (message.data?.serverSecret) {
          this.serverSecret = message.data.serverSecret;
          this.logger.info('Server secret received');
        }
        break;

      case 'execute_playbook':
        // Server requested playbook execution
        // Validate playbook ID format
        if (message.data?.playbook_id && typeof message.data.playbook_id === 'string') {
          if (!/^[a-zA-Z0-9\-_]+$/.test(message.data.playbook_id)) {
            this.logger.warn('Invalid playbook ID format');
            return;
          }
          this.logger.info('Server requested playbook execution', {
            playbook: message.data.playbook_id
          });
        }
        break;

      case 'update_config':
        // Server sent config update - validate before applying
        this.logger.info('Received config update from server');
        // Config updates should be validated by the handler
        break;

      case 'pong':
        // Heartbeat response
        break;

      case 'ack':
        // Message acknowledged
        break;

      default:
        this.logger.debug('Unhandled message type', { type: message.type });
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

  // Sanitize URL for logging (hide sensitive parts)
  private sanitizeUrl(url: string): string {
    try {
      const parsed = new URL(url);
      // Hide any auth info in URL
      parsed.username = '';
      parsed.password = '';
      return parsed.toString();
    } catch {
      return '[invalid url]';
    }
  }

  get connected(): boolean {
    return this.isConnected;
  }
}
