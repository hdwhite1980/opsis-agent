const Service = require('node-windows').Service;
const path = require('path');
const { execSync } = require('child_process');

// Add Windows Defender exclusions for the agent
function addDefenderExclusions() {
  const installDir = __dirname;
  const nodeExe = process.execPath;

  const exclusions = [
    // Exclude the install directory (agent code + data)
    `Add-MpPreference -ExclusionPath "${installDir}"`,
    // Exclude the Node.js process running the service
    `Add-MpPreference -ExclusionProcess "${nodeExe}"`,
  ];

  console.log('Adding Windows Defender exclusions...');
  for (const cmd of exclusions) {
    try {
      execSync(`powershell -Command "${cmd}"`, { timeout: 15000 });
    } catch (err) {
      // Non-fatal: Defender may not be installed, or exclusions may already exist
      console.log('  Note: Could not add Defender exclusion (may require admin or Defender not present)');
    }
  }
  console.log('  Defender exclusions configured');
}

// Create a new service object
const svc = new Service({
  name: 'OPSIS Agent Service',
  description: 'OPSIS Autonomous IT Management Agent - Monitors and automatically fixes system issues (Background Service)',
  script: path.join(__dirname, 'dist', 'index.js'),
  nodeOptions: [
    '--harmony',
    '--max_old_space_size=4096'
  ],
  env: [
    {
      name: "NODE_ENV",
      value: "production"
    },
    {
      name: "RUN_AS_SERVICE",
      value: "true"
    }
  ],
  workingDirectory: __dirname,
  allowServiceLogon: true,
  execPath: process.execPath, // Use current Node.js installation
  // Run as Local System for full permissions
  account: {
    domain: 'NT AUTHORITY',
    account: 'LocalSystem',
    password: ''
  }
});

// Listen for the "install" event
svc.on('install', function() {
  console.log('');
  console.log('');
  console.log(' OPSIS Agent Service Installed Successfully!');
  console.log('');
  console.log('');
  console.log('The agent is now running as a Windows Service with:');
  console.log('   Full administrator privileges');
  console.log('   Auto-start on system boot');
  console.log('   Runs even when logged out');
  console.log('');
  console.log('Starting service...');
  svc.start();
});

svc.on('alreadyinstalled', function() {
  console.log('  OPSIS Agent Service is already installed.');
  console.log('');
  console.log('To reinstall:');
  console.log('  1. Run: node uninstall-service.js');
  console.log('  2. Wait for uninstall to complete');
  console.log('  3. Run: node install-service.js');
  console.log('');
});

svc.on('start', function() {
  console.log('');
  console.log(' Service Started!');
  console.log('');
  console.log('');
  console.log(' MONITORING & MANAGEMENT:');
  console.log('');
  console.log('');
  console.log('View logs:');
  console.log('  ' + path.join(__dirname, 'logs', 'agent.log'));
  console.log('');
  console.log('Manage service:');
  console.log('   Open Services: Press Win+R, type "services.msc"');
  console.log('   Find: "OPSIS Agent Service"');
  console.log('   Right-click for Start/Stop/Restart');
  console.log('');
  console.log('Optional: Install GUI for monitoring');
  console.log('  Run: node install-startup.js');
  console.log('  (GUI will connect to the service)');
  console.log('');
  console.log('');
  console.log(' OPSIS Agent is now protecting your system!');
  console.log('');
  console.log('');
});

svc.on('error', function(err) {
  console.error(' Error:', err.message);
  console.error('');
  console.error('Common issues:');
  console.error('   Not running as Administrator');
  console.error('   Node.js path not found');
  console.error('   Service already exists (run uninstall first)');
  console.error('');
});

// Install the service
console.log('');
console.log('');
console.log(' Installing OPSIS Agent as Windows Service');
console.log('');
console.log('');
console.log('This will:');
console.log('   Add Windows Defender exclusions');
console.log('   Create a Windows Service');
console.log('   Configure auto-start on boot');
console.log('   Grant full administrator privileges');
console.log('');

addDefenderExclusions();
svc.install();
