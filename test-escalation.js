// Test script to send a fake escalation to the server and see the response
const WebSocket = require('ws');

const SERVER_URL = 'ws://178.156.234.101:8000/api/agent/ws/device-DESKTOP-JOGTI06';

const ws = new WebSocket(SERVER_URL);

ws.on('open', () => {
  console.log('Connected to server at', new Date().toISOString());

  // Send registration first
  ws.send(JSON.stringify({
    type: 'register',
    device_id: 'device-DESKTOP-JOGTI06',
    hostname: 'DESKTOP-JOGTI06',
    os_info: {
      platform: 'win32',
      release: '10.0.19045',
      arch: 'x64'
    }
  }));

  // Wait a moment then send fake escalation
  setTimeout(() => {
    const fakeEscalation = {
      type: 'escalation',
      tenant_id: '7',
      device_id: 'device-DESKTOP-JOGTI06',
      signature_id: 'TEST_HIGH_CPU_POWERSHELL_' + Date.now(),
      symptoms: [
        {
          type: 'performance',
          severity: 'high',
          details: {
            metric: 'cpu_usage',
            value: 98,
            threshold: 80,
            process_name: 'powershell.exe',
            process_id: 9999,
            duration_seconds: 600,
            description: 'PowerShell process consuming high CPU for extended period'
          }
        }
      ],
      targets: [
        {
          type: 'process',
          name: 'powershell.exe',
          identifier: '9999'
        }
      ],
      baseline_deviation_flags: {
        cpu_deviation: true,
        memory_deviation: false,
        disk_deviation: false,
        service_deviation: false
      },
      environment_tags: {
        os_build: '19045',
        os_version: 'Windows 10 Pro',
        app_versions: {},
        device_model_class: 'workstation'
      },
      recent_actions_summary: [],
      local_confidence: 65,
      requested_outcome: 'diagnose_root_cause'
    };

    console.log('\n--- Sending fake HIGH CPU escalation for powershell.exe ---');
    console.log(JSON.stringify(fakeEscalation, null, 2));
    ws.send(JSON.stringify(fakeEscalation));
  }, 1000);
});

let messageCount = 0;

ws.on('message', (data) => {
  messageCount++;
  const msg = JSON.parse(data.toString());
  console.log(`\n=== SERVER RESPONSE #${messageCount} ===`);
  console.log(JSON.stringify(msg, null, 2));
  console.log('========================\n');

  // If we got a playbook or decision, exit after a bit
  if (msg.type === 'playbook' || msg.type === 'decision' || msg.type === 'advisory' || msg.type === 'ignore') {
    setTimeout(() => {
      console.log('Test complete, closing connection');
      ws.close();
      process.exit(0);
    }, 2000);
  }
});

ws.on('error', (err) => {
  console.error('WebSocket error:', err.message);
  console.error('Full error:', err);
});

ws.on('unexpected-response', (req, res) => {
  console.error('Unexpected response:', res.statusCode, res.statusMessage);
});

ws.on('close', () => {
  console.log('Connection closed');
});

// Timeout after 5 minutes
setTimeout(() => {
  console.log(`\nTimeout after 5 minutes - received ${messageCount} messages total`);
  console.log('Closing connection...');
  ws.close();
  process.exit(0);
}, 300000);
