// scripts/install-service-exe.js - Install compiled OPSIS Agent exe as Windows Service
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const installDir = path.join(__dirname, '..');
const serviceDir = path.join(installDir, 'service');
const serviceName = 'OpsisAgentService';
const serviceExe = path.join(installDir, 'dist', 'opsis-agent-service.exe');

// Ensure service directory exists
if (!fs.existsSync(serviceDir)) {
  fs.mkdirSync(serviceDir, { recursive: true });
}

// Copy WinSW executable
const winswSource = path.join(installDir, 'node_modules', 'node-windows', 'bin', 'winsw', 'winsw.exe');
const winswDest = path.join(serviceDir, `${serviceName}.exe`);
const winswConfigDest = path.join(serviceDir, `${serviceName}.exe.config`);

console.log('Installing OPSIS Agent Service...');

// Copy winsw.exe as service wrapper
fs.copyFileSync(winswSource, winswDest);
fs.copyFileSync(winswSource + '.config', winswConfigDest);
console.log('  + Service wrapper copied');

// Create service configuration XML
const serviceXml = `<?xml version="1.0" encoding="UTF-8"?>
<service>
  <id>${serviceName}</id>
  <name>OPSIS Agent Service</name>
  <description>OPSIS Autonomous IT Management Agent - Monitors and fixes system issues automatically</description>
  <executable>${serviceExe}</executable>
  <arguments></arguments>
  <logmode>rotate</logmode>
  <logpath>${path.join(installDir, 'logs')}</logpath>
  <log mode="roll-by-size">
    <sizeThreshold>10240</sizeThreshold>
    <keepFiles>3</keepFiles>
  </log>
  <workingdirectory>${installDir}</workingdirectory>
  <priority>Normal</priority>
  <stoptimeout>30sec</stoptimeout>
  <stopparentprocessfirst>true</stopparentprocessfirst>
  <startmode>Automatic</startmode>
  <delayedAutoStart>false</delayedAutoStart>
  <env name="NODE_ENV" value="production"/>
  <onfailure action="restart" delay="10 sec"/>
  <onfailure action="restart" delay="20 sec"/>
  <onfailure action="none"/>
  <resetfailure>1 hour</resetfailure>
</service>
`;

const xmlPath = path.join(serviceDir, `${serviceName}.xml`);
fs.writeFileSync(xmlPath, serviceXml);
console.log('  + Service configuration created');

// Ensure logs directory exists
const logsDir = path.join(installDir, 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// Add Windows Defender exclusions
console.log('  + Adding Defender exclusions...');
try {
  execSync(`powershell -Command "Add-MpPreference -ExclusionPath '${installDir}'"`, { timeout: 15000, stdio: 'ignore' });
  execSync(`powershell -Command "Add-MpPreference -ExclusionProcess '${serviceExe}'"`, { timeout: 15000, stdio: 'ignore' });
} catch (err) {
  console.log('    Note: Could not add Defender exclusion (may need admin or Defender not present)');
}

// Install the service
console.log('  + Installing Windows service...');
try {
  execSync(`"${winswDest}" install`, { cwd: serviceDir, stdio: 'inherit' });
  console.log('  + Service installed');
} catch (err) {
  if (err.message.includes('already exists')) {
    console.log('  + Service already installed');
  } else {
    console.error('  ! Error installing service:', err.message);
    process.exit(1);
  }
}

// Start the service
console.log('  + Starting service...');
try {
  execSync(`"${winswDest}" start`, { cwd: serviceDir, stdio: 'inherit' });
  console.log('✓ OPSIS Agent Service started successfully!');
} catch (err) {
  console.log('  Note: Service may already be running');
}

console.log('');
console.log('Installation complete!');
console.log(`Service executable: ${serviceExe}`);
console.log(`Service logs: ${logsDir}`);
