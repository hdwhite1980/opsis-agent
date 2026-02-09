/**
 * OPSIS Agent Control Panel Web Server
 * Serves the control panel UI on localhost and routes WebSocket messages
 * to the agent service's existing IPC handlers.
 * Binds to localhost only. No new dependencies — uses Node built-in http + existing ws package.
 */

import * as http from 'http';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import WebSocket, { WebSocketServer } from 'ws';
import { Logger } from '../common/logger';

interface ControlPanelSession {
  id: string;
  ws: WebSocket;
  createdAt: number;
  lastActivity: number;
  messageCount: number;
  messageResetTime: number;
}

const MAX_CONCURRENT_SESSIONS = 5;
const SESSION_TIMEOUT_MS = 1800000; // 30 minutes
const MAX_MESSAGES_PER_MINUTE = 60;
const MAX_MESSAGE_SIZE = 8192;

export class ControlPanelServer {
  private server: http.Server | null = null;
  private wss: WebSocketServer | null = null;
  private logger: Logger;
  private port: number;
  private sessions: Map<string, ControlPanelSession> = new Map();
  private controlPanelHtml: string = '';
  private baseDir: string;
  private cleanupInterval: NodeJS.Timeout | null = null;

  // Callback: receives message type + data, returns response data
  public onRequest?: (type: string, data: any) => Promise<{ type: string; data: any } | null>;

  // Called when a new client connects (to send initial-data)
  public onClientConnected?: (sendFn: (msg: any) => void) => void;

  constructor(logger: Logger, baseDir: string, port: number = 19851) {
    this.logger = logger;
    this.port = port;
    this.baseDir = baseDir;
  }

  async start(): Promise<void> {
    // Load control panel HTML
    try {
      const srcPath = path.join(this.baseDir, 'src', 'gui', 'index.html');
      const distPath = path.join(this.baseDir, 'dist', 'gui', 'index.html');
      const relativePath = path.join(__dirname, '..', 'gui', 'index.html');

      if (fs.existsSync(srcPath)) {
        this.controlPanelHtml = fs.readFileSync(srcPath, 'utf-8');
      } else if (fs.existsSync(distPath)) {
        this.controlPanelHtml = fs.readFileSync(distPath, 'utf-8');
      } else if (fs.existsSync(relativePath)) {
        this.controlPanelHtml = fs.readFileSync(relativePath, 'utf-8');
      } else {
        this.logger.error('Control panel HTML not found', { tried: [srcPath, distPath, relativePath] });
        return;
      }
    } catch (error: any) {
      this.logger.error('Failed to load control panel HTML', error);
      return;
    }

    // Create HTTP server
    this.server = http.createServer((req, res) => {
      this.handleHttpRequest(req, res);
    });

    // Create WebSocket server
    this.wss = new WebSocketServer({ noServer: true });

    this.server.on('upgrade', (req, socket, head) => {
      if (req.url === '/ws') {
        // SECURITY: Verify Origin header to prevent cross-site WebSocket hijacking
        const origin = req.headers.origin;
        if (origin && !origin.match(/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/)) {
          this.logger.warn('Control panel WebSocket rejected: invalid origin', { origin });
          socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
          socket.destroy();
          return;
        }

        // Check concurrent session limit
        if (this.sessions.size >= MAX_CONCURRENT_SESSIONS) {
          socket.write('HTTP/1.1 503 Service Unavailable\r\n\r\n');
          socket.destroy();
          return;
        }
        this.wss!.handleUpgrade(req, socket, head, (ws) => {
          this.handleWebSocketConnection(ws);
        });
      } else {
        socket.destroy();
      }
    });

    // Bind to localhost only
    this.server.listen(this.port, '127.0.0.1', () => {
      this.logger.info('Control panel started', { url: `http://localhost:${this.port}` });
    });

    this.server.on('error', (error: any) => {
      if (error.code === 'EADDRINUSE') {
        this.logger.warn('Control panel port in use, trying alternate', { port: this.port });
        this.port++;
        this.server!.listen(this.port, '127.0.0.1');
      } else {
        this.logger.error('Control panel server error', error);
      }
    });

    // Clean up stale sessions periodically
    this.cleanupInterval = setInterval(() => this.cleanupSessions(), 60000);
  }

  stop(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }

    for (const [, session] of this.sessions) {
      session.ws.close(1001, 'Server shutting down');
    }
    this.sessions.clear();

    if (this.wss) {
      this.wss.close();
      this.wss = null;
    }

    if (this.server) {
      this.server.close();
      this.server = null;
    }

    this.logger.info('Control panel stopped');
  }

  private handleHttpRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
    // Security headers
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy',
      "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self' ws://localhost:* ws://127.0.0.1:*; img-src 'self' data:;");

    if (req.method === 'GET' && (req.url === '/' || req.url === '/index.html')) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(this.controlPanelHtml);
    } else if (req.method === 'GET' && req.url?.startsWith('/assets/')) {
      this.serveAsset(req, res);
    } else if (req.method === 'GET' && req.url === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', sessions: this.sessions.size }));
    } else {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
    }
  }

  private serveAsset(req: http.IncomingMessage, res: http.ServerResponse): void {
    // Extract filename — only allow basename (no path traversal)
    const urlPath = req.url!.substring(8); // strip /assets/
    const safeName = path.basename(urlPath);
    if (safeName !== urlPath || safeName.includes('..')) {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      res.end('Bad Request');
      return;
    }

    // Try multiple asset locations
    const candidates = [
      path.join(this.baseDir, 'src', 'gui', 'assets', safeName),
      path.join(this.baseDir, 'dist', 'gui', 'assets', safeName),
      path.join(this.baseDir, 'assets', safeName),
      path.join(__dirname, '..', 'gui', 'assets', safeName)
    ];

    for (const assetPath of candidates) {
      if (fs.existsSync(assetPath)) {
        const ext = path.extname(safeName).toLowerCase();
        const mimeTypes: Record<string, string> = {
          '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
          '.ico': 'image/x-icon', '.svg': 'image/svg+xml',
          '.css': 'text/css', '.js': 'application/javascript'
        };
        res.writeHead(200, {
          'Content-Type': mimeTypes[ext] || 'application/octet-stream',
          'Cache-Control': 'public, max-age=3600'
        });
        fs.createReadStream(assetPath).pipe(res);
        return;
      }
    }

    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
  }

  private handleWebSocketConnection(ws: WebSocket): void {
    const sessionId = crypto.randomBytes(16).toString('hex');
    const now = Date.now();

    const session: ControlPanelSession = {
      id: sessionId,
      ws,
      createdAt: now,
      lastActivity: now,
      messageCount: 0,
      messageResetTime: now + 60000
    };

    this.sessions.set(sessionId, session);
    this.logger.info('Control panel session started', { sessionId });

    // Send initial data to the new client
    if (this.onClientConnected) {
      this.onClientConnected((msg: any) => {
        this.sendToClient(ws, msg);
      });
    }

    ws.on('message', async (data) => {
      session.lastActivity = Date.now();

      const raw = data.toString();
      if (raw.length > MAX_MESSAGE_SIZE) {
        this.sendToClient(ws, { type: 'error', message: 'Message too long' });
        return;
      }

      if (!this.checkRateLimit(session)) {
        this.sendToClient(ws, { type: 'error', message: 'Too many messages. Please wait a moment.' });
        return;
      }

      try {
        const msg = JSON.parse(raw);
        await this.handleClientMessage(ws, msg);
      } catch {
        this.sendToClient(ws, { type: 'error', message: 'Invalid message format' });
      }
    });

    ws.on('close', () => {
      this.logger.info('Control panel session closed', { sessionId });
      this.sessions.delete(sessionId);
    });

    ws.on('error', (error) => {
      this.logger.error('Control panel WebSocket error', { sessionId, error: error.message });
      this.sessions.delete(sessionId);
    });
  }

  private async handleClientMessage(ws: WebSocket, msg: any): Promise<void> {
    if (!msg || typeof msg.type !== 'string') return;

    const requestId = msg.id; // may be undefined for fire-and-forget messages

    if (!this.onRequest) {
      if (requestId) {
        this.sendToClient(ws, { id: requestId, type: 'error', data: { message: 'No request handler configured' } });
      }
      return;
    }

    try {
      const response = await this.onRequest(msg.type, msg.data || {});
      if (response && requestId) {
        this.sendToClient(ws, { id: requestId, ...response });
      }
    } catch (error: any) {
      this.logger.error('Control panel request error', { type: msg.type, error: error.message });
      if (requestId) {
        this.sendToClient(ws, { id: requestId, type: 'error', data: { message: error.message } });
      }
    }
  }

  /** Broadcast a message to all connected control panel clients */
  broadcast(message: any): void {
    const payload = JSON.stringify(message);
    for (const [, session] of this.sessions) {
      if (session.ws.readyState === WebSocket.OPEN) {
        try {
          session.ws.send(payload);
        } catch (error: any) {
          this.logger.error('Failed to broadcast to control panel client', { error: error.message });
        }
      }
    }
  }

  /** Check if any control panel clients are connected */
  hasConnectedClients(): boolean {
    for (const [, session] of this.sessions) {
      if (session.ws.readyState === WebSocket.OPEN) return true;
    }
    return false;
  }

  private sendToClient(ws: WebSocket, message: any): void {
    if (ws.readyState === WebSocket.OPEN) {
      try {
        ws.send(JSON.stringify(message));
      } catch (error: any) {
        this.logger.error('Failed to send to control panel client', { error: error.message });
      }
    }
  }

  private checkRateLimit(session: ControlPanelSession): boolean {
    const now = Date.now();
    if (now > session.messageResetTime) {
      session.messageCount = 0;
      session.messageResetTime = now + 60000;
    }
    session.messageCount++;
    return session.messageCount <= MAX_MESSAGES_PER_MINUTE;
  }

  private cleanupSessions(): void {
    const now = Date.now();
    for (const [id, session] of this.sessions) {
      if (now - session.lastActivity > SESSION_TIMEOUT_MS) {
        this.logger.info('Cleaning up inactive control panel session', { sessionId: id });
        session.ws.close(1000, 'Session timeout');
        this.sessions.delete(id);
      }
    }
  }

  getPort(): number {
    return this.port;
  }

  getActiveSessions(): number {
    return this.sessions.size;
  }
}
