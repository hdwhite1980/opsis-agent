// ipc-server.ts - Named Pipe IPC Server for GUI Communication
import * as net from 'net';
import * as path from 'path';
import { Logger } from '../common/logger';

export interface IPCMessage {
  type: string;
  data?: any;
}

export class IPCServer {
  private server: net.Server | null = null;
  private pipeName: string;
  private logger: Logger;
  private clients: Set<net.Socket> = new Set();
  private messageHandlers: Map<string, (data: any, socket: net.Socket) => void> = new Map();
  private onClientConnectedCallback?: (socket: net.Socket) => void;

  private port: number;

  constructor(logger: Logger, pipeName: string = '\\\\.\\pipe\\opsis-agent-service', port: number = 19847) {
    this.logger = logger;
    this.pipeName = pipeName;
    this.port = port;
  }

  public start(): void {
    try {
      this.server = net.createServer((socket) => {
        this.handleClientConnection(socket);
      });

      // Use localhost TCP instead of named pipe to avoid SYSTEM→user permission issues
      this.server.listen(this.port, '127.0.0.1', () => {
        this.logger.info('IPC Server started', { port: this.port });
      });

      this.server.on('error', (error) => {
        this.logger.error('IPC Server error', error);
      });

    } catch (error) {
      this.logger.error('Failed to start IPC server', error);
    }
  }

  public stop(): void {
    // Close all client connections
    for (const client of this.clients) {
      client.destroy();
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
    this.logger.info('GUI client connected');
    this.clients.add(socket);

    let buffer = '';

    socket.on('data', (data) => {
      buffer += data.toString();

      // Process complete messages (newline-delimited JSON)
      const lines = buffer.split('\n');
      buffer = lines.pop() || ''; // Keep incomplete message in buffer

      for (const line of lines) {
        if (line.trim()) {
          try {
            const message: IPCMessage = JSON.parse(line);
            this.handleMessage(message, socket);
          } catch (error) {
            this.logger.error('Error parsing IPC message', error);
          }
        }
      }
    });

    socket.on('close', () => {
      this.logger.info('GUI client disconnected');
      this.clients.delete(socket);
    });

    socket.on('error', (error) => {
      this.logger.error('IPC client error', error);
      this.clients.delete(socket);
    });

    // Send welcome message
    this.sendToClient(socket, {
      type: 'connected',
      data: { status: 'ok' }
    });

    // Notify callback that client connected
    if (this.onClientConnectedCallback) {
      this.onClientConnectedCallback(socket);
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
      this.logger.warn('Unknown IPC message type', { type: message.type });
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
      const json = JSON.stringify(message) + '\n';
      socket.write(json);
    } catch (error) {
      this.logger.error('Error sending to client', error);
    }
  }

  public broadcast(message: IPCMessage): void {
    for (const client of this.clients) {
      this.sendToClient(client, message);
    }
  }
}

export default IPCServer;
