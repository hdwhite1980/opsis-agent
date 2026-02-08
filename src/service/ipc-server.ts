// ipc-server.ts - Secure IPC Server for GUI Communication
import * as net from 'net';
import * as crypto from 'crypto';
import { Logger } from '../common/logger';
import {
  signMessage,
  verifySignature,
  ensureIPCSecret,
  z,
  IPCMessageTypes,
  tryParseJSON
} from '../security';

export interface IPCMessage {
  type: string;
  data?: any;
  signature?: string;
  nonce?: string;
  timestamp?: string;
}

interface AuthenticatedClient {
  socket: net.Socket;
  authenticated: boolean;
  authAttempts: number;
  lastActivity: number;
}

// Rate limiting per client
interface RateLimitState {
  count: number;
  resetTime: number;
}

const MAX_AUTH_ATTEMPTS = 5;
const AUTH_LOCKOUT_MS = 300000; // 5 minutes
const MAX_REQUESTS_PER_MINUTE = 100;
const CLIENT_TIMEOUT_MS = 600000; // 10 minutes of inactivity

export class IPCServer {
  private server: net.Server | null = null;
  private logger: Logger;
  private clients: Map<net.Socket, AuthenticatedClient> = new Map();
  private messageHandlers: Map<string, (data: any, socket: net.Socket) => void> = new Map();
  private onClientConnectedCallback?: (socket: net.Socket) => void;
  private port: number;
  private ipcSecret: string = '';
  private rateLimits: Map<string, RateLimitState> = new Map();
  private requireAuth: boolean;

  // Allowed message types
  private readonly allowedTypes = new Set(IPCMessageTypes);

  constructor(
    logger: Logger,
    pipeName: string = '\\\\.\\pipe\\opsis-agent-service',
    port: number = 19847,
    requireAuth: boolean = true
  ) {
    this.logger = logger;
    this.port = port;
    this.requireAuth = requireAuth;
  }

  public async start(): Promise<void> {
    try {
      // Initialize IPC secret for authentication
      if (this.requireAuth) {
        this.ipcSecret = await ensureIPCSecret();
        this.logger.info('IPC authentication initialized');
      }

      this.server = net.createServer((socket) => {
        this.handleClientConnection(socket);
      });

      // Listen only on localhost
      this.server.listen(this.port, '127.0.0.1', () => {
        this.logger.info('IPC Server started', { port: this.port, authRequired: this.requireAuth });
      });

      this.server.on('error', (error) => {
        this.logger.error('IPC Server error', error);
      });

      // Clean up inactive clients periodically
      setInterval(() => this.cleanupInactiveClients(), 60000);

    } catch (error) {
      this.logger.error('Failed to start IPC server', error);
    }
  }

  public stop(): void {
    // Close all client connections
    for (const [socket] of this.clients) {
      socket.destroy();
    }
    this.clients.clear();

    // Close server
    if (this.server) {
      this.server.close();
      this.server = null;
    }

    this.logger.info('IPC Server stopped');
  }

  private handleClientConnection(socket: net.Socket): void {
    const clientId = `${socket.remoteAddress}:${socket.remotePort}`;
    this.logger.info('IPC client connecting', { clientId });

    // Initialize client state
    const client: AuthenticatedClient = {
      socket,
      authenticated: !this.requireAuth, // Auto-authenticated if auth disabled
      authAttempts: 0,
      lastActivity: Date.now()
    };
    this.clients.set(socket, client);

    let buffer = '';

    socket.on('data', (data) => {
      client.lastActivity = Date.now();
      buffer += data.toString();

      // Limit buffer size to prevent memory exhaustion
      if (buffer.length > 1048576) { // 1MB
        this.logger.warn('IPC buffer overflow, disconnecting client', { clientId });
        socket.destroy();
        return;
      }

      // Process complete messages (newline-delimited JSON)
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const line of lines) {
        if (line.trim()) {
          this.processMessage(line, socket, client, clientId);
        }
      }
    });

    socket.on('close', () => {
      this.logger.info('IPC client disconnected', { clientId });
      this.clients.delete(socket);
      this.rateLimits.delete(clientId);
    });

    socket.on('error', (error) => {
      this.logger.error('IPC client error', { clientId, error: error.message });
      this.clients.delete(socket);
    });

    // Send challenge for authentication
    if (this.requireAuth) {
      const challenge = crypto.randomBytes(32).toString('hex');
      this.sendToClient(socket, {
        type: 'auth_challenge',
        data: { challenge }
      });
    } else {
      // No auth required, send welcome directly
      this.sendToClient(socket, {
        type: 'connected',
        data: { status: 'ok' }
      });

      if (this.onClientConnectedCallback) {
        this.onClientConnectedCallback(socket);
      }
    }
  }

  private processMessage(line: string, socket: net.Socket, client: AuthenticatedClient, clientId: string): void {
    try {
      // SECURITY: Use safe JSON parsing
      const { parsed, error: parseError } = tryParseJSON(line);
      if (parseError || !parsed) {
        this.logger.warn('Invalid JSON from IPC client', { clientId, error: parseError });
        return;
      }
      const message = parsed as IPCMessage;

      // Validate message structure
      if (!message || typeof message !== 'object' || typeof message.type !== 'string') {
        this.logger.warn('Invalid IPC message structure', { clientId });
        return;
      }

      // Check rate limit
      if (!this.checkRateLimit(clientId)) {
        this.logger.warn('IPC rate limit exceeded', { clientId });
        this.sendToClient(socket, {
          type: 'error',
          data: { message: 'Rate limit exceeded' }
        });
        return;
      }

      // Handle authentication
      if (message.type === 'auth_response') {
        this.handleAuthResponse(message, socket, client, clientId);
        return;
      }

      // Require authentication for all other messages
      if (this.requireAuth && !client.authenticated) {
        this.logger.warn('Unauthenticated IPC request', { clientId, type: message.type });
        this.sendToClient(socket, {
          type: 'error',
          data: { message: 'Authentication required' }
        });
        return;
      }

      // Validate message type is allowed
      if (!this.allowedTypes.has(message.type as any)) {
        this.logger.warn('Unknown IPC message type', { clientId, type: message.type });
        return;
      }

      // Verify signature if provided (extra security layer)
      if (message.signature && message.nonce && message.timestamp) {
        const { type, data } = message;
        const verification = verifySignature(
          { type, data },
          message.signature,
          message.nonce,
          message.timestamp,
          this.ipcSecret
        );
        if (!verification.valid) {
          this.logger.warn('Invalid IPC message signature', { clientId, error: verification.error });
          return;
        }
      }

      // Handle the message
      this.handleMessage(message, socket);

    } catch (error) {
      this.logger.error('Error processing IPC message', { clientId, error: (error as Error).message });
    }
  }

  private handleAuthResponse(message: IPCMessage, socket: net.Socket, client: AuthenticatedClient, clientId: string): void {
    // Check if locked out
    if (client.authAttempts >= MAX_AUTH_ATTEMPTS) {
      this.logger.warn('IPC client locked out', { clientId });
      this.sendToClient(socket, {
        type: 'error',
        data: { message: 'Too many failed attempts. Try again later.' }
      });
      socket.destroy();
      return;
    }

    const { response, challenge } = message.data || {};

    if (!response || !challenge) {
      client.authAttempts++;
      this.sendToClient(socket, {
        type: 'auth_failed',
        data: { message: 'Invalid auth response' }
      });
      return;
    }

    // Verify the response (HMAC of challenge with secret)
    const expectedResponse = crypto
      .createHmac('sha256', this.ipcSecret)
      .update(challenge)
      .digest('hex');

    // Constant-time comparison
    const responseBuffer = Buffer.from(response, 'hex');
    const expectedBuffer = Buffer.from(expectedResponse, 'hex');

    if (responseBuffer.length !== expectedBuffer.length ||
        !crypto.timingSafeEqual(responseBuffer, expectedBuffer)) {
      client.authAttempts++;
      this.logger.warn('IPC auth failed', { clientId, attempts: client.authAttempts });
      this.sendToClient(socket, {
        type: 'auth_failed',
        data: { message: 'Authentication failed' }
      });
      return;
    }

    // Authentication successful
    client.authenticated = true;
    client.authAttempts = 0;
    this.logger.info('IPC client authenticated', { clientId });

    this.sendToClient(socket, {
      type: 'connected',
      data: { status: 'ok', authenticated: true }
    });

    if (this.onClientConnectedCallback) {
      this.onClientConnectedCallback(socket);
    }
  }

  private checkRateLimit(clientId: string): boolean {
    const now = Date.now();
    let state = this.rateLimits.get(clientId);

    if (!state || now > state.resetTime) {
      state = { count: 0, resetTime: now + 60000 };
      this.rateLimits.set(clientId, state);
    }

    state.count++;
    return state.count <= MAX_REQUESTS_PER_MINUTE;
  }

  private cleanupInactiveClients(): void {
    const now = Date.now();
    for (const [socket, client] of this.clients) {
      if (now - client.lastActivity > CLIENT_TIMEOUT_MS) {
        this.logger.info('Closing inactive IPC client');
        socket.destroy();
        this.clients.delete(socket);
      }
    }
  }

  private handleMessage(message: IPCMessage, socket: net.Socket): void {
    this.logger.info('IPC message received', { type: message.type });

    const handler = this.messageHandlers.get(message.type);
    if (handler) {
      try {
        handler(message.data, socket);
      } catch (error) {
        this.logger.error('Error handling IPC message', error);
        this.sendToClient(socket, {
          type: 'error',
          data: { message: 'Error processing request' }
        });
      }
    } else {
      this.logger.warn('No handler for IPC message type', { type: message.type });
    }
  }

  public onMessage(type: string, handler: (data: any, socket: net.Socket) => void): void {
    this.messageHandlers.set(type, handler);
  }

  public onClientConnected(callback: (socket: net.Socket) => void): void {
    this.onClientConnectedCallback = callback;
  }

  public sendToClient(socket: net.Socket, message: IPCMessage): void {
    try {
      // Sign outgoing messages
      if (this.requireAuth && this.ipcSecret) {
        const { signature, nonce, timestamp } = signMessage(
          { type: message.type, data: message.data },
          this.ipcSecret
        );
        message.signature = signature;
        message.nonce = nonce;
        message.timestamp = timestamp;
      }

      const json = JSON.stringify(message) + '\n';
      socket.write(json);
    } catch (error) {
      this.logger.error('Error sending to client', error);
    }
  }

  public broadcast(message: IPCMessage): void {
    for (const [socket, client] of this.clients) {
      if (client.authenticated || !this.requireAuth) {
        this.sendToClient(socket, message);
      }
    }
  }

  // Get IPC secret for GUI to use in authentication
  public getIPCSecret(): string {
    return this.ipcSecret;
  }
}

export default IPCServer;
