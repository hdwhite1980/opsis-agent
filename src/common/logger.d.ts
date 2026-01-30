export declare enum LogLevel {
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
export declare class Logger {
    private logDir;
    private logFile;
    private component;
    private minLevel;
    private maxFileSize;
    private maxFiles;
    constructor(component: string, logDir: string, minLevel?: LogLevel);
    private rotateLogsIfNeeded;
    private formatMessage;
    private writeLog;
    debug(message: string, data?: any): void;
    info(message: string, data?: any): void;
    warn(message: string, data?: any, error?: any): void;
    error(message: string, error?: any, data?: any): void;
    critical(message: string, error?: any, data?: any): void;
    startOperation(operation: string, context?: any): void;
    endOperation(operation: string, success: boolean, result?: any): void;
    logPlaybookExecution(playbookId: string, step: string, status: string, details?: any): void;
    logServiceAction(action: string, target: string, result: string, error?: any): void;
    logDatabaseOperation(operation: string, table: string, affected?: number): void;
    logNetworkEvent(event: string, endpoint?: string, status?: number): void;
    getRecentLogs(lines?: number): string[];
    searchLogs(query: string, maxResults?: number): string[];
    clearOldLogs(daysToKeep?: number): void;
}
export declare function getServiceLogger(logDir: string): Logger;
export declare function getGUILogger(logDir: string): Logger;
export default Logger;
//# sourceMappingURL=logger.d.ts.map