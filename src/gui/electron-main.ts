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
    connectToService();
    createWindow();
    createTray();
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
  return nativeImage.createEmpty();
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
          const logPath = path.join(app.getPath('userData'), '..', '..', 'logs', 'agent.log');
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
          exec('net stop "OPSIS Agent Service" && net start "OPSIS Agent Service"');
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

function connectToService() {
  const pipeName = '\\\\.\\pipe\\opsis-agent-service';
  const fs = require('fs');
  const logPath = path.join(__dirname, '..', '..', 'logs', 'gui-connection.log');
  
  const log = (msg: string) => {
    const timestamp = new Date().toISOString();
    const logMsg = `[${timestamp}] ${msg}\n`;
    console.log(msg);
    try {
      fs.appendFileSync(logPath, logMsg);
    } catch (err) {
      console.error('Failed to write log:', err);
    }
  };
  
  log(`Attempting to connect to: ${pipeName}`);
  let buffer = '';
  
  serviceConnection = net.connect(pipeName, () => {
    log('Connected to OPSIS Agent Service');
  });

  serviceConnection.on('data', (data: Buffer) => {
    buffer += data.toString();
    
    // Process complete messages (newline-delimited)
    const lines = buffer.split('\n');
    buffer = lines.pop() || ''; // Keep incomplete message in buffer
    
    for (const line of lines) {
      if (line.trim()) {
        try {
          const message = JSON.parse(line);
          handleServiceMessage(message);
        } catch (err) {
          log(`Error parsing service message: ${err}`);
        }
      }
    }
  });

  serviceConnection.on('error', (err: Error) => {
    log(`Service connection error: ${err.message}`);
    // Retry connection after 5 seconds
    setTimeout(connectToService, 5000);
  });

  serviceConnection.on('close', () => {
    log('Disconnected from service, reconnecting...');
    setTimeout(connectToService, 5000);
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
    // Send tickets
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('tickets-data', message.data.tickets || []);
      
      // Also send stats if available
      if (message.data.stats) {
        mainWindow.webContents.send('stats-data', message.data.stats);
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
    // Stats response
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('stats-data', message.data);
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

ipcMain.on('update-settings', (_event: any, settings: any) => {
  sendToService({
    type: 'update-settings',
    data: settings
  });
});

// Service responses come back via handleServiceMessage and are forwarded to renderer

export {};
