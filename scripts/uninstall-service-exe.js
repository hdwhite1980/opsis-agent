// scripts/uninstall-service-exe.js - Uninstall compiled OPSIS Agent service
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const installDir = path.join(__dirname, '..');
const serviceDir = path.join(installDir, 'service');
const serviceName = 'OpsisAgentService';
const winswExe = path.join(serviceDir, `${serviceName}.exe`);

console.log('Uninstalling OPSIS Agent Service...');

if (!fs.existsSync(winswExe)) {
  console.log('Service wrapper not found - service may not be installed');
  process.exit(0);
}

// Stop the service
console.log('  + Stopping service...');
try {
  execSync(`"${winswExe}" stop`, { cwd: serviceDir, stdio: 'inherit', timeout: 30000 });
  console.log('  + Service stopped');
} catch (err) {
  console.log('  Note: Service may not be running');
}

// Wait a moment for service to fully stop
execSync('timeout /t 2 /nobreak >nul', { shell: true });

// Uninstall the service
console.log('  + Removing service...');
try {
  execSync(`"${winswExe}" uninstall`, { cwd: serviceDir, stdio: 'inherit' });
  console.log('  + Service removed');
} catch (err) {
  console.log('  Note: Service may already be removed');
}

// Clean up service files
console.log('  + Cleaning up service files...');
try {
  fs.unlinkSync(path.join(serviceDir, `${serviceName}.exe`));
  fs.unlinkSync(path.join(serviceDir, `${serviceName}.exe.config`));
  fs.unlinkSync(path.join(serviceDir, `${serviceName}.xml`));
  fs.rmdirSync(serviceDir);
} catch (err) {
  // Files may not exist
}

console.log('✓ OPSIS Agent Service uninstalled successfully!');
