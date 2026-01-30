export interface ServerConfig {
  serverUrl: string;
  websocketUrl: string;
  apiKey: string;
  agentId: string;
  clientId: string;
  reconnectInterval: number;
  heartbeatInterval: number;
}

export const DEFAULT_SERVER_CONFIG: ServerConfig = {
  serverUrl: 'http://localhost:8000',
  websocketUrl: 'ws://localhost:8000/ws',
  apiKey: '',
  agentId: '',
  clientId: '',
  reconnectInterval: 30000,  // 30 seconds
  heartbeatInterval: 60000   // 60 seconds
};
