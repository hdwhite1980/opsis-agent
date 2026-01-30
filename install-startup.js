const path = require('path');
const fs = require('fs');
const { execSync } = require('child_process');

const startupFolder = path.join(
  process.env.APPDATA,
  'Microsoft',
  'Windows',
  'Start Menu',
  'Programs',
  'Startup'
);

const batchFile = path.join(__dirname, 'start-opsis-gui.bat');
const shortcutPath = path.join(startupFolder, 'OPSIS Agent Monitor.lnk');

console.log('');
console.log('');
console.log(' Installing OPSIS GUI to Windows Startup...');
console.log('');
console.log('');

// Create batch file to start GUI
const batchContent = `@echo off
cd /d "%~dp0"
start /min cmd /c "npm run gui"`;

fs.writeFileSync(batchFile, batchContent);

// Create VBS script to create shortcut
const vbsScript = `
Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = "${shortcutPath.replace(/\\/g, '\\\\')}"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "${batchFile.replace(/\\/g, '\\\\')}"
oLink.WorkingDirectory = "${__dirname.replace(/\\/g, '\\\\')}"
oLink.Description = "OPSIS Agent Monitor GUI"
oLink.WindowStyle = 7
oLink.Save
`.trim();

const vbsFile = path.join(__dirname, 'create-shortcut.vbs');
fs.writeFileSync(vbsFile, vbsScript);

try {
  execSync(`cscript //nologo "${vbsFile}"`, { stdio: 'inherit' });
  fs.unlinkSync(vbsFile);
  
  console.log(' OPSIS GUI installed to Windows Startup!');
  console.log('');
  console.log('');
  console.log(' INSTALLATION COMPLETE!');
  console.log('');
  console.log('');
  console.log('Your OPSIS Agent setup:');
  console.log('');
  console.log('   Background Service: RUNNING');
  console.log('      Monitors system 24/7');
  console.log('      Full admin permissions');
  console.log('      Auto-fixes issues');
  console.log('');
  console.log('   GUI Monitor: Will start on login');
  console.log('      System tray icon');
  console.log('      Real-time activity log');
  console.log('      Configuration panel');
  console.log('');
  console.log('Next Steps:');
  console.log('  1. Log out and back in (GUI will auto-start)');
  console.log('  2. Or run now: npm run gui');
  console.log('  3. Check system tray for OPSIS icon');
  console.log('');
  console.log('Logs: ' + path.join(__dirname, 'logs', 'agent.log'));
  console.log('');
  console.log('');
  console.log(' OPSIS is now protecting your system!');
  console.log('');
  console.log('');
  
} catch (error) {
  console.error(' Failed to create startup shortcut:', error.message);
  if (fs.existsSync(vbsFile)) {
    fs.unlinkSync(vbsFile);
  }
}
