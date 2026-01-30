// electron-main.js - Complete file with sql.js
const { app, BrowserWindow, Tray, Menu, ipcMain, nativeImage } = require('electron');
const path = require('path');
const fs = require('fs');

let mainWindow = null;
let tray = null;
let isQuitting = false;

// Single instance lock
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
    
    // Clear old tickets on startup
    setTimeout(() => {
      clearOldTickets();
    }, 5000);
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js')
    },
    icon: getIcon('icon.png')
  });

  mainWindow.loadFile(path.join(__dirname, 'src', 'gui', 'index.html'));

  mainWindow.on('close', (event) => {
    if (!isQuitting) {
      event.preventDefault();
      mainWindow.hide();
      
      // Show balloon notification first time
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

function getIcon(iconName) {
  const iconPath = path.join(__dirname, 'assets', iconName);
  if (fs.existsSync(iconPath)) {
    return nativeImage.createFromPath(iconPath);
  }
  return nativeImage.createEmpty();
}

function createTray() {
  try {
    tray = new Tray(getIcon('tray-icon.png') || getIcon('icon.png'));
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
          const logPath = path.join(__dirname, 'logs', 'agent.log');
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
          exec('net stop "OPSIS Agent Service" && net start "OPSIS Agent Service"', (err) => {
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
// SQL.JS DATABASE HELPER
// ============================================

async function getDatabase() {
  try {
    const initSqlJs = require('sql.js');
    const SQL = await initSqlJs();
    const dbPath = path.join(__dirname, 'data', 'agent.db');
    
    // Create data directory if it doesn't exist
    const dataDir = path.join(__dirname, 'data');
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }
    
    // If database doesn't exist, return null
    if (!fs.existsSync(dbPath)) {
      console.log('Database not found at:', dbPath);
      return null;
    }
    
    // Load database from file
    const buffer = fs.readFileSync(dbPath);
    const db = new SQL.Database(buffer);
    
    return db;
  } catch (err) {
    console.error('Error loading database:', err);
    return null;
  }
}

function saveDatabase(db, dbPath) {
  try {
    const data = db.export();
    const buffer = Buffer.from(data);
    fs.writeFileSync(dbPath, buffer);
    return true;
  } catch (err) {
    console.error('Error saving database:', err);
    return false;
  }
}

// ============================================
// IPC HANDLERS
// ============================================

// Get statistics
ipcMain.on('get-stats', async (event) => {
  try {
    const db = await getDatabase();
    
    if (!db) {
      return event.reply('stats-data', {
        issuesDetected: 0,
        issuesEscalated: 0,
        successRate: 0
      });
    }
    
    const getValue = (sql) => {
      try {
        const result = db.exec(sql);
        if (result.length > 0 && result[0].values.length > 0) {
          return result[0].values[0][0] || 0;
        }
        return 0;
      } catch (err) {
        console.error('SQL error:', sql, err);
        return 0;
      }
    };
    
    const issuesDetected = getValue('SELECT COUNT(*) FROM local_tickets');
    const issuesEscalated = getValue('SELECT COUNT(*) FROM local_tickets WHERE escalated = 1');
    const successCount = getValue("SELECT COUNT(*) FROM local_tickets WHERE result = 'success'");
    const totalCount = getValue('SELECT COUNT(*) FROM local_tickets WHERE result IS NOT NULL');
    
    const successRate = totalCount > 0 ? Math.round((successCount / totalCount) * 100) : 0;
    
    db.close();
    
    event.reply('stats-data', {
      issuesDetected,
      issuesEscalated,
      successRate
    });
  } catch (err) {
    console.error('Error getting stats:', err);
    event.reply('stats-data', {
      issuesDetected: 0,
      issuesEscalated: 0,
      successRate: 0
    });
  }
});

// Get tickets
ipcMain.on('get-tickets', async (event) => {
  try {
    const db = await getDatabase();
    
    if (!db) {
      return event.reply('tickets-data', []);
    }
    
    const result = db.exec('SELECT * FROM local_tickets ORDER BY created_at DESC LIMIT 100');
    const tickets = [];
    
    if (result.length > 0) {
      const columns = result[0].columns;
      const values = result[0].values;
      
      values.forEach(row => {
        const ticket = {};
        columns.forEach((col, i) => {
          ticket[col] = row[i];
        });
        tickets.push(ticket);
      });
    }
    
    db.close();
    event.reply('tickets-data', tickets);
  } catch (err) {
    console.error('Error getting tickets:', err);
    event.reply('tickets-data', []);
  }
});

// Clear old tickets
ipcMain.on('clear-old-tickets', async (event) => {
  try {
    const db = await getDatabase();
    
    if (!db) {
      return event.reply('tickets-cleared', 0);
    }
    
    const dbPath = path.join(__dirname, 'data', 'agent.db');
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    
    // Delete old tickets
    db.run('DELETE FROM local_tickets WHERE created_at < ?', [oneDayAgo]);
    
    // Get number of changes
    const result = db.exec('SELECT changes()');
    const changes = result[0]?.values[0]?.[0] || 0;
    
    // Save database
    saveDatabase(db, dbPath);
    
    db.close();
    event.reply('tickets-cleared', changes);
  } catch (err) {
    console.error('Error clearing tickets:', err);
    event.reply('tickets-cleared', 0);
  }
});

// Auto-clear old tickets on startup
async function clearOldTickets() {
  try {
    const db = await getDatabase();
    if (!db) return;
    
    const dbPath = path.join(__dirname, 'data', 'agent.db');
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    
    db.run('DELETE FROM local_tickets WHERE created_at < ?', [oneDayAgo]);
    saveDatabase(db, dbPath);
    
    db.close();
    console.log('Auto-cleared old tickets on startup');
  } catch (err) {
    console.error('Error auto-clearing tickets:', err);
  }
}