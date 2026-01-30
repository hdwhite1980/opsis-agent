export interface MonitoringConfig {
  interval: number;
  metricsRetentionDays: number;
}

export interface ExecutionConfig {
  enabled: boolean;
  requireApprovalForRiskB: boolean;
  requireApprovalForRiskC: boolean;
  maxConcurrentExecutions: number;
}

export interface AIConfig {
  tier1Enabled: boolean;
  tier2Enabled: boolean;
  tier3Enabled: boolean;
  confidenceThreshold: number;
}

export interface ServerConfig {
  enabled: boolean;
  url: string;
  websocketUrl: string;
  apiKey: string;
}

export interface AgentConfig {
  agentId: string;
  clientId: string;
  monitoring: MonitoringConfig;
  execution: ExecutionConfig;
  ai: AIConfig;
  server: ServerConfig;
}

const defaultConfig: AgentConfig = {
  agentId: 'agent-001',
  clientId: 'client-001',
  monitoring: {
    interval: 30000,
    metricsRetentionDays: 30
  },
  execution: {
    enabled: true,
    requireApprovalForRiskB: false,
    requireApprovalForRiskC: true,
    maxConcurrentExecutions: 3
  },
  ai: {
    tier1Enabled: true,
    tier2Enabled: true,
    tier3Enabled: true,
    confidenceThreshold: 75
  },
  server: {
    enabled: false,
    url: 'http://localhost:8000',
    websocketUrl: 'ws://localhost:8000/ws',
    apiKey: ''
  }
};

export function loadConfig(): AgentConfig {
  try {
    const fs = require('fs');
    const configFile = fs.readFileSync('./agent.config.json', 'utf-8');
    const userConfig = JSON.parse(configFile);
    
    const config = {
      ...defaultConfig,
      ...userConfig,
      monitoring: { ...defaultConfig.monitoring, ...userConfig.monitoring },
      execution: { ...defaultConfig.execution, ...userConfig.execution },
      ai: { ...defaultConfig.ai, ...userConfig.ai },
      server: { ...defaultConfig.server, ...userConfig.server }
    };

    if (config.server.enabled && !config.server.apiKey) {
      console.warn('WARNING: Server is enabled but API key is empty. Server communication may fail.');
    }

    return config;
  } catch (error) {
    console.warn('No config file found, using defaults');
    return defaultConfig;
  }
}
