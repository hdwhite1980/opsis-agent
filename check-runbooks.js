const data = require('./data/server-runbooks.json');

// Find Spooler runbooks
const spooler = data.runbooks.filter(r => r.name.includes('Spooler') || r.name.includes('Print'));
console.log('=== PRINT SPOOLER PLAYBOOKS FROM SERVER ===\n');
spooler.forEach(r => {
  console.log('ID:', r.id);
  console.log('Name:', r.name);
  console.log('Saved at:', r.saved_at);
  console.log('Steps:', JSON.stringify(r.steps, null, 2));
  console.log('---\n');
});

// Group Policy diagnostics
console.log('\n=== GROUP POLICY (GPSVC) DIAGNOSTIC ===\n');
console.log('Session ID: diag-8d99ec45fe1f');
console.log('Commands:');
const gpsvcCommands = [
  { command: "Get-Service -Name gpsvc | Select-Object Name, Status, StartType, ServiceType", description: "Check current Group Policy Client service status and configuration", timeout: 15 },
  { command: "Get-WinEvent -LogName System -FilterHashtable @{ID=7034,7036,7040} | Where-Object {$_.Message -like '*gpsvc*'} | Select-Object -First 10", description: "Check recent service control manager events for gpsvc", timeout: 30 },
  { command: "Get-Service -Name RpcSs, RpcEptMapper, DcomLaunch, EventLog | Select-Object Name, Status", description: "Verify critical service dependencies are running", timeout: 15 },
  { command: "Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\GPExtensions'", description: "Verify Group Policy registry structure exists", timeout: 10 },
  { command: "Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\GPExtensions' -ErrorAction SilentlyContinue | Measure-Object", description: "Count Group Policy extensions in registry", timeout: 15 },
  { command: "whoami /priv | findstr SeServiceLogonRight", description: "Check if current context has service logon privileges", timeout: 10 },
  { command: "sc.exe qc gpsvc", description: "Query Group Policy Client service configuration details", timeout: 15 },
  { command: "Get-WmiObject -Class Win32_Service -Filter \"Name='gpsvc'\" | Select-Object ProcessId, State, ErrorControl", description: "Get detailed WMI service information for gpsvc", timeout: 20 },
  { command: "Get-Process -Name svchost | Where-Object {$_.Modules.ModuleName -contains 'gpsvc.dll'} -ErrorAction SilentlyContinue", description: "Check if gpsvc.dll is loaded in any svchost process", timeout: 20 },
  { command: "Test-Path '$env:SystemRoot\\System32\\gpsvc.dll'", description: "Verify Group Policy Client service binary exists", timeout: 10 },
  { command: "Get-Acl 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' | Select-Object Owner, AccessToString", description: "Check registry permissions on Winlogon key", timeout: 15 },
  { command: "gpresult /r", description: "Attempt to generate Group Policy results to test functionality", timeout: 45 },
  { command: "Get-WinEvent -LogName 'Microsoft-Windows-GroupPolicy/Operational' -MaxEvents 20 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, LevelDisplayName, Message", description: "Check Group Policy operational log for recent errors", timeout: 30 },
  { command: "sfc /verifyonly", description: "Check system file integrity without repair", timeout: 300 },
  { command: "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\gpsvc' -ErrorAction SilentlyContinue | Select-Object Start, Type, ErrorControl, ImagePath", description: "Verify gpsvc service registry configuration", timeout: 15 }
];
gpsvcCommands.forEach((c, i) => {
  console.log(`\n${i+1}. ${c.description}`);
  console.log(`   Command: ${c.command}`);
  console.log(`   Timeout: ${c.timeout}s`);
});

console.log('\n\n=== CPU HIGH USAGE (POWERSHELL) ===\n');
console.log('Status: Server acknowledged with "processing with AI..." but no playbook received yet');
console.log('This was a test escalation - server may not have a specific playbook for this scenario');
