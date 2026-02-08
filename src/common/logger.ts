// logger.ts - Centralized logging utility for OPSIS Agent
import * as fs from 'fs';
import * as path from 'path';
import { sanitizeLogData } from '../security';

export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
  CRITICAL = 4
}

export interface LogEntry {
  timestamp: string;
  level: string;
  component: string;
  message: string;
  data?: any;
  error?: any;
}

export class Logger {
  private logDir: string;
  private logFile: string;
  private component: string;
  private minLevel: LogLevel;
  private maxFileSize: number = 10 * 1024 * 1024; // 10MB
  private maxFiles: number = 5;

  constructor(component: string, logDir: string, minLevel: LogLevel = LogLevel.INFO) {
    this.component = component;
    this.logDir = logDir;
    this.minLevel = minLevel;
    
    // Create log directory if it doesn't exist
    if (!fs.existsSync(logDir)) {
      fs.mkdirSync(logDir, { recursive: true });
    }

    // Set log file path
    this.logFile = path.join(logDir, `${component}.log`);
    
    // Rotate logs if needed
    this.rotateLogsIfNeeded();
  }

  private rotateLogsIfNeeded(): void {
    try {
      if (!fs.existsSync(this.logFile)) {
        return;
      }

      const stats = fs.statSync(this.logFile);
      
      if (stats.size >= this.maxFileSize) {
        // Rotate existing logs
        for (let i = this.maxFiles - 1; i > 0; i--) {
          const oldFile = `${this.logFile}.${i}`;
          const newFile = `${this.logFile}.${i + 1}`;
          
          if (fs.existsSync(oldFile)) {
            if (i === this.maxFiles - 1) {
              fs.unlinkSync(oldFile); // Delete oldest
            } else {
              fs.renameSync(oldFile, newFile);
            }
          }
        }
        
        // Rotate current log
        fs.renameSync(this.logFile, `${this.logFile}.1`);
      }
    } catch (error) {
      console.error('Error rotating logs:', error);
    }
  }

  private formatMessage(level: LogLevel, message: string, data?: any, error?: any): string {
    const timestamp = new Date().toISOString();
    const levelName = LogLevel[level];

    // Sanitize message to remove sensitive data
    const sanitizedMessage = sanitizeLogData(message) as string;
    let logLine = `[${timestamp}] [${levelName}] [${this.component}] ${sanitizedMessage}`;

    if (data) {
      // Sanitize data object to redact sensitive fields
      const sanitizedData = sanitizeLogData(data);
      logLine += `\n  Data: ${JSON.stringify(sanitizedData, null, 2)}`;
    }

    if (error) {
      // Sanitize error message and stack trace
      const errorMessage = sanitizeLogData(error.message || String(error)) as string;
      logLine += `\n  Error: ${errorMessage}`;
      if (error.stack && level >= LogLevel.ERROR) {
        // Only include stack traces for ERROR and above, and sanitize them
        const sanitizedStack = sanitizeLogData(error.stack) as string;
        logLine += `\n  Stack: ${sanitizedStack}`;
      }
    }

    return logLine + '\n';
  }

  private writeLog(level: LogLevel, message: string, data?: any, error?: any): void {
    if (level < this.minLevel) {
      return;
    }

    const logMessage = this.formatMessage(level, message, data, error);
    
    // Write to console
    if (level >= LogLevel.WARN) {
      console.error(logMessage.trim());
    } else {
      console.log(logMessage.trim());
    }
    
    // Write to file
    try {
      fs.appendFileSync(this.logFile, logMessage);
      
      // Check if rotation needed after write
      this.rotateLogsIfNeeded();
    } catch (err) {
      console.error('Failed to write log:', err);
    }
  }

  public debug(message: string, data?: any): void {
    this.writeLog(LogLevel.DEBUG, message, data);
  }

  public info(message: string, data?: any): void {
    this.writeLog(LogLevel.INFO, message, data);
  }

  public warn(message: string, data?: any, error?: any): void {
    this.writeLog(LogLevel.WARN, message, data, error);
  }

  public error(message: string, error?: any, data?: any): void {
    this.writeLog(LogLevel.ERROR, message, data, error);
  }

  public critical(message: string, error?: any, data?: any): void {
    this.writeLog(LogLevel.CRITICAL, message, data, error);
  }

  // Convenience methods for common patterns
  public startOperation(operation: string, context?: any): void {
    this.info(`Starting: ${operation}`, context);
  }

  public endOperation(operation: string, success: boolean, result?: any): void {
    if (success) {
      this.info(`Completed: ${operation}`, result);
    } else {
      this.error(`Failed: ${operation}`, result);
    }
  }

  public logPlaybookExecution(playbookId: string, step: string, status: string, details?: any): void {
    this.info(`Playbook [${playbookId}] - ${step}: ${status}`, details);
  }

  public logServiceAction(action: string, target: string, result: string, error?: any): void {
    if (error) {
      this.error(`Service action failed: ${action} on ${target}`, error, { result });
    } else {
      this.info(`Service action: ${action} on ${target} - ${result}`);
    }
  }

  public logDatabaseOperation(operation: string, table: string, affected?: number): void {
    this.debug(`Database: ${operation} on ${table}`, { affected });
  }

  public logNetworkEvent(event: string, endpoint?: string, status?: number): void {
    this.info(`Network: ${event}`, { endpoint, status });
  }

  // Get recent logs for UI display
  public getRecentLogs(lines: number = 100): string[] {
    try {
      if (!fs.existsSync(this.logFile)) {
        return [];
      }

      const content = fs.readFileSync(this.logFile, 'utf8');
      const allLines = content.split('\n').filter(line => line.trim());
      
      return allLines.slice(-lines);
    } catch (error) {
      console.error('Error reading logs:', error);
      return [];
    }
  }

  // Search logs
  public searchLogs(query: string, maxResults: number = 50): string[] {
    try {
      if (!fs.existsSync(this.logFile)) {
        return [];
      }

      const content = fs.readFileSync(this.logFile, 'utf8');
      const allLines = content.split('\n');
      
      const results = allLines
        .filter(line => line.toLowerCase().includes(query.toLowerCase()))
        .slice(-maxResults);
      
      return results;
    } catch (error) {
      console.error('Error searching logs:', error);
      return [];
    }
  }

  // Clear old logs
  public clearOldLogs(daysToKeep: number = 30): void {
    try {
      const cutoffTime = Date.now() - (daysToKeep * 24 * 60 * 60 * 1000);
      
      // Check all rotated log files
      for (let i = 1; i <= this.maxFiles; i++) {
        const logFile = `${this.logFile}.${i}`;
        
        if (fs.existsSync(logFile)) {
          const stats = fs.statSync(logFile);
          
          if (stats.mtimeMs < cutoffTime) {
            fs.unlinkSync(logFile);
            this.info(`Deleted old log file: ${path.basename(logFile)}`);
          }
        }
      }
    } catch (error) {
      this.error('Error clearing old logs', error);
    }
  }
}

// Create singleton loggers for different components
let serviceLogger: Logger | null = null;
let guiLogger: Logger | null = null;

export function getServiceLogger(logDir: string): Logger {
  if (!serviceLogger) {
    serviceLogger = new Logger('service', logDir, LogLevel.INFO);
  }
  return serviceLogger;
}

export function getGUILogger(logDir: string): Logger {
  if (!guiLogger) {
    guiLogger = new Logger('gui', logDir, LogLevel.INFO);
  }
  return guiLogger;
}

// Export default for convenience
export default Logger;
