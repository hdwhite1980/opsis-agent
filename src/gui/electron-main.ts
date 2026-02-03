// electron-main.ts - Production GUI (runs as current user)
const { app, BrowserWindow, Tray, Menu, ipcMain, nativeImage } = require('electron');
const path = require('path');
const fs = require('fs');
const net = require('net');

let mainWindow: any = null;
let tray: any = null;
let isQuitting = false;
let serviceConnection: any = null;

const gotTheLock = app.requestSingleInstanceLock();

if (!gotTheLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      if (!mainWindow.isVisible()) mainWindow.show();
      mainWindow.focus();
    }
  });

  app.whenReady().then(() => {
    createWindow();
    createTray();
    connectToService();
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false
    },
    icon: getIcon('icon.ico') || getIcon('icon.png') || getIcon('opsis-logo-icon.png'),
    show: false // Don't show until ready
  });

  mainWindow.loadFile(path.join(__dirname, 'index.html'));

  mainWindow.once('ready-to-show', () => {
    // Only show if not starting minimized
    if (!app.getLoginItemSettings().wasOpenedAsHidden) {
      mainWindow.show();
    }
  });

  mainWindow.on('close', (event: any) => {
    if (!isQuitting) {
      event.preventDefault();
      mainWindow.hide();
      
      if (tray && !mainWindow.wasHiddenBefore) {
        tray.displayBalloon({
          title: 'OPSIS Agent',
          content: 'Still running in system tray. Double-click icon to reopen.'
        });
        mainWindow.wasHiddenBefore = true;
      }
    }
  });
}

function getIcon(iconName: string) {
  const iconPath = path.join(__dirname, 'assets', iconName);
  if (fs.existsSync(iconPath)) {
    return nativeImage.createFromPath(iconPath);
  }
  return null;
}

function createTray() {
  try {
    const trayIcon = getIcon('icon.ico') || getIcon('tray-icon.png') || getIcon('icon.png');
    tray = new Tray(trayIcon);
    tray.setToolTip('OPSIS Agent - Autonomous IT Management');
    
    const contextMenu = Menu.buildFromTemplate([
      {
        label: 'Show Control Panel',
        click: () => {
          mainWindow.show();
          mainWindow.focus();
        }
      },
      {
        label: 'View Logs',
        click: () => {
          const { shell } = require('electron');
          const logPath = path.join(__dirname, '..', '..', 'logs', 'service.log');
          if (fs.existsSync(logPath)) {
            shell.openPath(logPath);
          }
        }
      },
      { type: 'separator' },
      {
        label: 'Restart Service',
        click: () => {
          const { exec } = require('child_process');
          exec('net stop "OPSIS Agent Service" && net start "OPSIS Agent Service"', (err: any) => {
            if (err) {
              console.error('Failed to restart service:', err);
            }
          });
        }
      },
      { type: 'separator' },
      {
        label: 'Quit',
        click: () => {
          isQuitting = true;
          app.quit();
        }
      }
    ]);
    
    tray.setContextMenu(contextMenu);
    
    tray.on('double-click', () => {
      mainWindow.show();
      mainWindow.focus();
    });
  } catch (err) {
    console.error('Tray creation error:', err);
  }
}

app.on('window-all-closed', () => {
  // Don't quit - stay in tray
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});

// ============================================
// SERVICE COMMUNICATION (IPC over Named Pipe)
// ============================================

let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let isConnected = false;

function scheduleReconnect(reason: string) {
  isConnected = false;
  if (reconnectTimer) return;
  console.log(`${reason}, reconnecting in 5s...`);
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    connectToService();
  }, 5000);
}

function connectToService() {
  const ipcPort = 19847;
  // Clean up any existing connection
  if (serviceConnection) {
    try { serviceConnection.destroy(); } catch (e) {}
    serviceConnection = null;
  }
  console.log(`Attempting to connect to localhost:${ipcPort}`);
  let buffer = '';
  const conn = net.connect({ port: ipcPort, host: '127.0.0.1' }, () => {
    console.log('Connected to OPSIS Agent Service');
    isConnected = true;
    // Request data immediately after connecting
    setTimeout(() => {
      if (conn.writable) {
        console.log('Requesting initial data from service...');
        conn.write(JSON.stringify({ type: 'get-stats' }) + '\n');
        conn.write(JSON.stringify({ type: 'get-tickets' }) + '\n');
        conn.write(JSON.stringify({ type: 'get-health-data' }) + '\n');
      }
    }, 500);
  });
  serviceConnection = conn;
  conn.on('data', (data: Buffer) => {
    buffer += data.toString();
    const lines = buffer.split('\n');
    buffer = lines.pop() || '';
    for (const line of lines) {
      if (line.trim()) {
        try {
          const message = JSON.parse(line);
          handleServiceMessage(message);
        } catch (err) {
          console.error(`Error parsing service message: ${err}`);
        }
      }
    }
  });
  conn.on('error', (err: Error) => {
    if (serviceConnection === conn) {
      scheduleReconnect(`Service connection error: ${err.message}`);
    }
  });
  conn.on('close', () => {
    if (serviceConnection === conn) {
      scheduleReconnect('Disconnected from service');
    }
  });
}

function sendToService(message: any) {
  console.log('Attempting to send to service:', message.type);
  if (serviceConnection && serviceConnection.writable) {
    console.log('Connection is writable, sending...');
    serviceConnection.write(JSON.stringify(message) + '\n');
  } else {
    console.error('Cannot send to service - connection not writable:', {
      exists: !!serviceConnection,
      writable: serviceConnection?.writable
    });
  }
}

function handleServiceMessage(message: any) {
  console.log('Received from service:', message.type);
  
  // Transform service messages to match what GUI expects
  if (message.type === 'initial-data' || message.type === 'ticket-update') {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('tickets-data', message.data.tickets || []);

      if (message.data.stats) {
        mainWindow.webContents.send('stats-data', message.data.stats);
      }
      // Forward health data if present
      if (message.data.healthScores || message.data.correlations || message.data.patterns || message.data.proactiveActions) {
        mainWindow.webContents.send('health-data', {
          healthScores: message.data.healthScores || {},
          correlations: message.data.correlations || {},
          patterns: message.data.patterns || [],
          proactiveActions: message.data.proactiveActions || []
        });
      }
      // Forward service alerts if present (from initial-data)
      if (message.data.serviceAlerts && message.data.serviceAlerts.length > 0) {
        mainWindow.webContents.send('service-alerts', message.data.serviceAlerts);
      }
    }
  } else if (message.type === 'tickets') {
    // Direct tickets response
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('tickets-data', message.data.tickets || message.data || []);
      
      if (message.data.stats) {
        mainWindow.webContents.send('stats-data', message.data.stats);
      }
    }
  } else if (message.type === 'stats') {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('stats-data', message.data);
    }
  } else if (message.type === 'health-data') {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('health-data', message.data);
    }
  } else if (message.type === 'service-alert') {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('service-alert', message.data);
    }
    // Show tray balloon for visibility even when minimized
    if (tray && message.data) {
      const severity = message.data.severity === 'outage' ? 'OUTAGE' :
                       message.data.severity === 'major' ? 'Issue' : 'Advisory';
      tray.displayBalloon({
        title: `${message.data.service || 'Service'} ${severity}`,
        content: message.data.message || message.data.title || 'A cloud service issue may affect you.'
      });
    }
  } else if (message.type === 'service-alert-resolved') {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('service-alert-resolved', message.data);
    }
  } else if (message.type === 'service-alerts') {
    // Response to get-service-alerts request
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('service-alerts', message.data);
    }
  } else if (message.type === 'user-prompt') {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('user-prompt', message.data);
      // Bring window to front for user prompts
      if (!mainWindow.isVisible()) {
        mainWindow.show();
      }
      mainWindow.focus();
    }
  } else {
    // Forward other messages as-is
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('service-message', message);
    }
  }
}

// ============================================
// IPC HANDLERS (GUI -> Service)
// ============================================

ipcMain.on('get-stats', (_event: any) => {
  sendToService({ type: 'get-stats' });
});

ipcMain.on('get-tickets', (_event: any) => {
  sendToService({ type: 'get-tickets' });
});

ipcMain.on('clear-old-tickets', (_event: any) => {
  sendToService({ type: 'clear-old-tickets' });
});

ipcMain.on('submit-manual-ticket', (_event: any, ticketData: any) => {
  sendToService({ 
    type: 'submit-manual-ticket',
    data: ticketData
  });
});

ipcMain.on('get-health-data', (_event: any) => {
  sendToService({ type: 'get-health-data' });
});

ipcMain.on('get-service-alerts', (_event: any) => {
  sendToService({ type: 'get-service-alerts' });
});

ipcMain.on('dismiss-alert', (_event: any, alertId: string) => {
  sendToService({ type: 'dismiss-alert', data: { alertId } });
});

ipcMain.on('update-settings', (_event: any, settings: any) => {
  sendToService({
    type: 'update-settings',
    data: settings
  });
});

ipcMain.on('user-prompt-response', (_event: any, data: any) => {
  sendToService({
    type: 'user-prompt-response',
    data
  });
});

// Service responses come back via handleServiceMessage and are forwarded to renderer

export {};
