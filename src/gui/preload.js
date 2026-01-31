const { contextBridge, ipcRenderer } = require('electron');

const validSendChannels = [
  'get-stats',
  'get-tickets',
  'get-health-data',
  'get-service-alerts',
  'clear-old-tickets',
  'submit-manual-ticket',
  'dismiss-alert',
  'update-settings'
];

const validReceiveChannels = [
  'stats-data',
  'tickets-data',
  'tickets-cleared',
  'health-data',
  'service-alert',
  'service-alerts',
  'service-alert-resolved',
  'service-message'
];

contextBridge.exposeInMainWorld('ipcRenderer', {
  send: (channel, ...args) => {
    if (validSendChannels.includes(channel)) {
      ipcRenderer.send(channel, ...args);
    }
  },
  on: (channel, func) => {
    if (validReceiveChannels.includes(channel)) {
      ipcRenderer.on(channel, func);
    }
  },
  removeAllListeners: (channel) => {
    if (validReceiveChannels.includes(channel)) {
      ipcRenderer.removeAllListeners(channel);
    }
  }
});
