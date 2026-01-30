// scripts/install-service.js - Install OPSIS Agent as Windows Service
const Service = require('node-windows').Service;
const path = require('path');
const { execSync } = require('child_process');

// Add Windows Defender exclusions for the agent
function addDefenderExclusions() {
  const installDir = path.join(__dirname, '..');
  const nodeExe = process.execPath;

  const exclusions = [
    `Add-MpPreference -ExclusionPath "${installDir}"`,
    `Add-MpPreference -ExclusionProcess "${nodeExe}"`,
  ];

  console.log('Adding Windows Defender exclusions...');
  for (const cmd of exclusions) {
    try {
      execSync(`powershell -Command "${cmd}"`, { timeout: 15000 });
    } catch (err) {
      console.log('  Note: Could not add Defender exclusion (may require admin or Defender not present)');
    }
  }
  console.log('  Defender exclusions configured');
}

console.log('Installing OPSIS Agent Service...');
addDefenderExclusions();

// Path to the compiled service
const servicePath = path.join(__dirname, '..', 'dist', 'service', 'agent-service.js');

// Create a new service object
const svc = new Service({
  name: 'OPSIS Agent Service',
  description: 'OPSIS Autonomous IT Management Agent - Monitors and fixes system issues automatically',
  script: servicePath,
  nodeOptions: [],
  env: [{
    name: 'NODE_ENV',
    value: 'production'
  }],
  wait: 2,
  grow: 0.5,
  maxRestarts: 10
});

// Listen for the "install" event
svc.on('install', function() {
  console.log('✓ Service installed successfully!');
  console.log('Starting service...');
  svc.start();
});

svc.on('alreadyinstalled', function() {
  console.log('⚠ Service is already installed');
  console.log('Run uninstall-service.js first if you want to reinstall');
});

svc.on('start', function() {
  console.log('✓ Service started successfully!');
  console.log('');
  console.log('OPSIS Agent Service is now running');
  console.log('Check status: Get-Service "OPSIS Agent Service"');
  console.log('View logs: C:\\Program Files\\OPSIS Agent\\logs\\agent.log');
  process.exit(0);
});

svc.on('error', function(err) {
  console.error('✗ Error:', err);
  process.exit(1);
});

// Install the service
svc.install();
