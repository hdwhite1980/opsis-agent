// scripts/uninstall-service.js - Uninstall OPSIS Agent Windows Service
const Service = require('node-windows').Service;
const path = require('path');

console.log('Uninstalling OPSIS Agent Service...');

// Path to the compiled service
const servicePath = path.join(__dirname, '..', 'dist', 'service', 'agent-service.js');

// Create a new service object
const svc = new Service({
  name: 'OPSIS Agent Service',
  script: servicePath
});

// Listen for the "uninstall" event
svc.on('uninstall', function() {
  console.log('✓ Service uninstalled successfully');
  console.log('');
  console.log('Note: Logs and data have been preserved');
  console.log('Location: C:\\Program Files\\OPSIS Agent\\');
  process.exit(0);
});

svc.on('alreadyuninstalled', function() {
  console.log('⚠ Service is not installed');
  process.exit(0);
});

svc.on('error', function(err) {
  console.error('✗ Error:', err);
  process.exit(1);
});

// Check if service exists
svc.on('doesnotexist', function() {
  console.log('⚠ Service does not exist');
  process.exit(0);
});

// Uninstall the service
svc.uninstall();
