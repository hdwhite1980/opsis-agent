/**
 * OPSIS Agent Self-Service Portal Server
 * Lightweight HTTP + WebSocket server for end-user self-service issue resolution.
 * Binds to localhost only. No new dependencies — uses Node built-in http + existing ws package.
 */

import * as http from 'http';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import WebSocket, { WebSocketServer } from 'ws';
import { Logger } from '../common/logger';
import { ConversationEngine, ConversationCallback } from './conversation-engine';
import { TroubleshootingRunner } from './troubleshooting-runner';
import { Primitives } from '../execution/primitives';
import { ActionTicketManager } from './action-ticket-manager';
import { TicketDatabase } from './ticket-database';

interface PortalSession {
  id: string;
  ws: WebSocket;
  createdAt: number;
  lastActivity: number;
  messageCount: number;
  messageResetTime: number;
  diagnosticRuns: number;
  fixRuns: number;
  hourResetTime: number;
}

const MAX_CONCURRENT_SESSIONS = 3;
const SESSION_TIMEOUT_MS = 1800000; // 30 minutes
const MAX_MESSAGES_PER_MINUTE = 30;
const MAX_DIAGNOSTICS_PER_HOUR = 5;
const MAX_FIXES_PER_HOUR = 10;
const MAX_MESSAGE_SIZE = 2048;

export class SelfServiceServer {
  private server: http.Server | null = null;
  private wss: WebSocketServer | null = null;
  private logger: Logger;
  private port: number;
  private sessions: Map<string, PortalSession> = new Map();
  private engine: ConversationEngine;
  private portalHtml: string = '';
  private baseDir: string;
  private cleanupInterval: NodeJS.Timeout | null = null;

  // Callback for sending telemetry to the OPSIS server
  public onResolution?: (data: {
    category: string;
    resolution_time_seconds: number;
    user_satisfaction?: number;
    fix_applied?: string;
    auto_resolved: boolean;
    session_messages: number;
    ticket_id?: string;
  }) => void;

  // Callback for AI escalation via server WebSocket
  public onEscalation?: (data: {
    session_id: string;
    user_description: string;
    category: string;
    diagnostic_data: any;
  }) => Promise<{
    analysis: string;
    suggested_fix?: { type: string; primitive?: string; params?: Record<string, any> };
    suggested_fix_description?: string;
  } | null>;

  constructor(
    logger: Logger,
    troubleshootingRunner: TroubleshootingRunner,
    actionTicketManager: ActionTicketManager,
    ticketDb: TicketDatabase,
    baseDir: string,
    port: number = 19850
  ) {
    this.logger = logger;
    this.port = port;
    this.baseDir = baseDir;

    // Create a Primitives instance for the conversation engine
    const primitives = new Primitives(logger);

    this.engine = new ConversationEngine(
      logger,
      troubleshootingRunner,
      primitives,
      actionTicketManager,
      ticketDb
    );
  }

  async start(): Promise<void> {
    // Load portal HTML
    try {
      const portalPath = path.join(this.baseDir, 'src', 'portal', 'portal.html');
      // Try source directory first, then dist
      if (fs.existsSync(portalPath)) {
        this.portalHtml = fs.readFileSync(portalPath, 'utf-8');
      } else {
        const distPath = path.join(this.baseDir, 'dist', 'portal', 'portal.html');
        if (fs.existsSync(distPath)) {
          this.portalHtml = fs.readFileSync(distPath, 'utf-8');
        } else {
          // Fallback: look relative to this file's compiled location
          const relativePath = path.join(__dirname, '..', 'portal', 'portal.html');
          if (fs.existsSync(relativePath)) {
            this.portalHtml = fs.readFileSync(relativePath, 'utf-8');
          } else {
            this.logger.error('Portal HTML not found', { tried: [portalPath, distPath, relativePath] });
            return;
          }
        }
      }
    } catch (error: any) {
      this.logger.error('Failed to load portal HTML', error);
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
      this.logger.info('Self-service portal started', { url: `http://localhost:${this.port}` });
    });

    this.server.on('error', (error: any) => {
      if (error.code === 'EADDRINUSE') {
        this.logger.warn('Self-service portal port in use, trying alternate', { port: this.port });
        this.port++;
        this.server!.listen(this.port, '127.0.0.1');
      } else {
        this.logger.error('Self-service portal server error', error);
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

    this.logger.info('Self-service portal stopped');
  }

  private handleHttpRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
    // Security headers
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self' ws://localhost:*;");

    if (req.method === 'GET' && (req.url === '/' || req.url === '/index.html')) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(this.portalHtml);
    } else if (req.method === 'GET' && req.url === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', sessions: this.sessions.size }));
    } else {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
    }
  }

  private handleWebSocketConnection(ws: WebSocket): void {
    const sessionId = crypto.randomBytes(16).toString('hex');
    const now = Date.now();

    const session: PortalSession = {
      id: sessionId,
      ws,
      createdAt: now,
      lastActivity: now,
      messageCount: 0,
      messageResetTime: now + 60000,
      diagnosticRuns: 0,
      fixRuns: 0,
      hourResetTime: now + 3600000
    };

    this.sessions.set(sessionId, session);
    this.logger.info('Self-service portal session started', { sessionId });

    // Create conversation callback for sending messages to browser
    const callback: ConversationCallback = {
      sendMessage: (text: string, metadata?: any) => {
        this.sendToClient(ws, { type: 'agent-message', text, metadata });
      },
      sendProgress: (step: number, total: number, description: string) => {
        this.sendToClient(ws, { type: 'progress', step, total, description });
      },
      sendFindings: (findings: any[]) => {
        this.sendToClient(ws, { type: 'findings', findings });
      },
      sendFixResult: (success: boolean, message: string) => {
        this.sendToClient(ws, { type: 'fix-result', success, message });
      },
      sendSatisfactionPrompt: () => {
        this.sendToClient(ws, { type: 'satisfaction-prompt' });
      },
      requestEscalation: async (data) => {
        if (this.onEscalation) {
          return this.onEscalation({ session_id: sessionId, ...data });
        }
        return null;
      }
    };

    // Initialize conversation
    this.engine.createSession(sessionId, callback);

    // Send session ID to client
    this.sendToClient(ws, { type: 'session-init', sessionId });

    ws.on('message', (data) => {
      session.lastActivity = Date.now();

      // Size check
      const raw = data.toString();
      if (raw.length > MAX_MESSAGE_SIZE) {
        this.sendToClient(ws, { type: 'error', message: 'Message too long' });
        return;
      }

      // Rate limit
      if (!this.checkRateLimit(session)) {
        this.sendToClient(ws, { type: 'error', message: 'Too many messages. Please wait a moment.' });
        return;
      }

      try {
        const msg = JSON.parse(raw);
        this.handleClientMessage(sessionId, msg, session);
      } catch {
        this.sendToClient(ws, { type: 'error', message: 'Invalid message format' });
      }
    });

    ws.on('close', () => {
      this.logger.info('Self-service portal session closed', { sessionId });
      this.engine.endSession(sessionId);
      this.sessions.delete(sessionId);
    });

    ws.on('error', (error) => {
      this.logger.error('Self-service portal WebSocket error', { sessionId, error: error.message });
      this.engine.endSession(sessionId);
      this.sessions.delete(sessionId);
    });
  }

  private async handleClientMessage(sessionId: string, msg: any, session: PortalSession): Promise<void> {
    if (!msg || typeof msg.type !== 'string') return;

    switch (msg.type) {
      case 'user-message':
        if (typeof msg.text === 'string' && msg.text.trim().length > 0) {
          await this.engine.processMessage(sessionId, msg.text.trim());
        }
        break;

      case 'quick-pick':
        if (typeof msg.category === 'string') {
          await this.engine.processQuickPick(sessionId, msg.category);
        }
        break;

      case 'approve-fix':
        if (typeof msg.fixIndex === 'number') {
          session.fixRuns++;
          await this.engine.approveFix(sessionId, msg.fixIndex);
        }
        break;

      case 'decline-fix':
        await this.engine.declineFix(sessionId);
        break;

      case 'satisfaction':
        if (typeof msg.rating === 'number' && msg.rating >= 1 && msg.rating <= 5) {
          const resolution = this.engine.completeSatisfaction(sessionId, msg.rating);
          if (resolution && this.onResolution) {
            this.onResolution(resolution);
          }
        }
        break;

      default:
        this.logger.warn('Unknown self-service message type', { type: msg.type });
    }
  }

  private sendToClient(ws: WebSocket, message: any): void {
    if (ws.readyState === WebSocket.OPEN) {
      try {
        ws.send(JSON.stringify(message));
      } catch (error: any) {
        this.logger.error('Failed to send to portal client', { error: error.message });
      }
    }
  }

  private checkRateLimit(session: PortalSession): boolean {
    const now = Date.now();

    // Reset per-minute counter
    if (now > session.messageResetTime) {
      session.messageCount = 0;
      session.messageResetTime = now + 60000;
    }

    // Reset hourly counters
    if (now > session.hourResetTime) {
      session.diagnosticRuns = 0;
      session.fixRuns = 0;
      session.hourResetTime = now + 3600000;
    }

    session.messageCount++;
    return session.messageCount <= MAX_MESSAGES_PER_MINUTE;
  }

  private cleanupSessions(): void {
    const now = Date.now();
    for (const [id, session] of this.sessions) {
      if (now - session.lastActivity > SESSION_TIMEOUT_MS) {
        this.logger.info('Cleaning up inactive portal session', { sessionId: id });
        session.ws.close(1000, 'Session timeout');
        this.engine.endSession(id);
        this.sessions.delete(id);
      }
    }
  }

  /** Handle AI escalation response from server */
  handleEscalationResponse(sessionId: string, response: any): void {
    this.engine.handleEscalationResponse(sessionId, response);
  }

  getPort(): number {
    return this.port;
  }

  getActiveSessions(): number {
    return this.sessions.size;
  }
}
