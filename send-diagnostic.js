// Send diagnostic results to server
const WebSocket = require('ws');
const { execSync } = require('child_process');

const SERVER_URL = 'ws://178.156.234.101:8000/api/agent/ws/device-DESKTOP-JOGTI06';

const ws = new WebSocket(SERVER_URL);

// Run a command and return output
function runCmd(cmd) {
  try {
    const output = execSync(`powershell -Command "${cmd}"`, { encoding: 'utf8', timeout: 30000 });
    return { success: true, output: output.trim(), error: null, exit_code: 0 };
  } catch (e) {
    return { success: false, output: null, error: e.message, exit_code: e.status || -1 };
  }
}

ws.on('open', () => {
  console.log('Connected to server');

  // Send registration
  ws.send(JSON.stringify({
    type: 'register',
    device_id: 'device-DESKTOP-JOGTI06',
    hostname: 'DESKTOP-JOGTI06'
  }));

  setTimeout(() => {
    console.log('\nRunning gpsvc diagnostics...\n');

    const commands = [
      { cmd: "Get-Service -Name gpsvc | Select-Object Name, Status, StartType, ServiceType | Format-List", desc: "Service status" },
      { cmd: "sc.exe query gpsvc", desc: "SC query" },
      { cmd: "sc.exe qc gpsvc", desc: "SC config" },
      { cmd: "Get-WmiObject -Class Win32_Service -Filter \\\"Name='gpsvc'\\\" | Select-Object Name, State, StartMode, ProcessId, ExitCode | Format-List", desc: "WMI service info" },
      { cmd: "Get-EventLog -LogName System -Source 'Service Control Manager' -Newest 10 | Where-Object {$_.Message -like '*gpsvc*'} | Select-Object TimeGenerated, EntryType, Message", desc: "Recent gpsvc events" }
    ];

    const results = [];
    commands.forEach((c, i) => {
      console.log(`Running step-${i}: ${c.desc}`);
      const result = runCmd(c.cmd);
      console.log(`  Success: ${result.success}`);
      if (result.output) console.log(`  Output: ${result.output.substring(0, 200)}...`);
      results.push({
        step_id: `step-${i}`,
        ...result,
        parsed_result: null
      });
    });

    const diagnosticResult = {
      type: 'diagnostic_result',
      timestamp: new Date().toISOString(),
      device_id: 'device-DESKTOP-JOGTI06',
      session_id: 'diag-gpsvc-manual-' + Date.now(),
      results,
      command_count: results.length,
      all_success: results.every(r => r.success)
    };

    console.log('\n--- Sending diagnostic results to server ---');
    console.log(`Session: ${diagnosticResult.session_id}`);
    console.log(`Commands: ${diagnosticResult.command_count}`);
    console.log(`All success: ${diagnosticResult.all_success}`);

    ws.send(JSON.stringify(diagnosticResult));
    console.log('\nDiagnostic results sent!');

  }, 1000);
});

ws.on('message', (data) => {
  const msg = JSON.parse(data.toString());
  console.log('\n=== SERVER RESPONSE ===');
  console.log(JSON.stringify(msg, null, 2));
  console.log('========================\n');

  if (msg.type === 'diagnostic_ack' || msg.type === 'playbook') {
    setTimeout(() => {
      ws.close();
      process.exit(0);
    }, 2000);
  }
});

ws.on('error', (err) => console.error('Error:', err.message));
ws.on('close', () => console.log('Connection closed'));

setTimeout(() => {
  console.log('Timeout - closing');
  ws.close();
  process.exit(0);
}, 60000);
