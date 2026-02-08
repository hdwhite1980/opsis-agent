/**
 * Test Escalation Script
 * Sends a fake issue directly to the OPSIS server via WebSocket
 *
 * Usage: node test-escalation.js [type]
 *
 * Types:
 *   high-cpu        - High CPU from powershell.exe (default)
 *   disk-space-low  - Low disk space on C:
 *   service-stopped - Stopped service (Spooler)
 *   high-memory     - High memory usage
 */

const WebSocket = require('ws');

const SERVER_URL = 'wss://opsisapp.com/api/agent/ws/device-DESKTOP-JOGTI06';
const issueType = process.argv[2] || 'high-cpu';

console.log(`\n=== OPSIS Test Escalation ===`);
console.log(`Server: ${SERVER_URL}`);
console.log(`Issue Type: ${issueType}\n`);

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
      release: '10.0.22631',
      arch: 'x64'
    }
  }));

  // Build escalation based on type
  setTimeout(() => {
    let escalation = {
      type: 'escalation',
      tenant_id: '7',
      device_id: 'device-DESKTOP-JOGTI06',
      signature_id: `TEST_${issueType.toUpperCase().replace(/-/g, '_')}_${Date.now()}`,
      symptoms: [],
      targets: [],
      baseline_deviation_flags: {
        cpu_deviation: false,
        memory_deviation: false,
        disk_deviation: false,
        service_deviation: false
      },
      environment_tags: {
        os_build: '22631',
        os_version: 'Windows 11 Pro',
        app_versions: {},
        device_model_class: 'workstation'
      },
      recent_actions_summary: [],
      local_confidence: 60,
      requested_outcome: 'diagnose_root_cause'
    };

    switch (issueType) {
      case 'high-cpu':
        escalation.symptoms = [{
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
        }];
        escalation.targets = [{ type: 'process', name: 'powershell.exe', identifier: '9999' }];
        escalation.baseline_deviation_flags.cpu_deviation = true;
        break;

      case 'disk-space-low':
        escalation.symptoms = [{
          type: 'disk',
          severity: 'high',
          details: {
            drive: 'C:',
            free_percent: 3,
            free_gb: 5,
            total_gb: 256,
            threshold: 10,
            description: 'Critical disk space - only 3% free'
          }
        }];
        escalation.targets = [{ type: 'system', name: 'C:', identifier: 'disk-c' }];
        escalation.baseline_deviation_flags.disk_deviation = true;
        escalation.requested_outcome = 'recommend_playbook';
        break;

      case 'service-stopped':
        escalation.symptoms = [{
          type: 'service_status',
          severity: 'high',
          details: {
            service: 'Spooler',
            display_name: 'Print Spooler',
            state: 'Stopped',
            expected: 'Running',
            description: 'Print Spooler service has stopped unexpectedly'
          }
        }];
        escalation.targets = [{ type: 'service', name: 'Spooler', identifier: 'spooler' }];
        escalation.baseline_deviation_flags.service_deviation = true;
        escalation.requested_outcome = 'recommend_playbook';
        break;

      case 'high-memory':
        escalation.symptoms = [{
          type: 'performance',
          severity: 'high',
          details: {
            metric: 'memory_usage',
            value: 95,
            threshold: 85,
            available_mb: 800,
            total_mb: 16384,
            description: 'System memory critically low'
          }
        }];
        escalation.targets = [{ type: 'system', name: 'Memory', identifier: 'ram' }];
        escalation.baseline_deviation_flags.memory_deviation = true;
        break;

      default:
        console.log('Unknown issue type, using high-cpu');
        return;
    }

    console.log(`\n--- Sending ${issueType} escalation ---`);
    console.log('Signature ID:', escalation.signature_id);
    console.log('Symptoms:', JSON.stringify(escalation.symptoms, null, 2));
    console.log('\nWaiting for server response...\n');

    ws.send(JSON.stringify(escalation));
  }, 1000);
});

let messageCount = 0;

ws.on('message', (data) => {
  messageCount++;
  const msg = JSON.parse(data.toString());
  console.log(`\n=== SERVER RESPONSE #${messageCount} ===`);
  console.log('Type:', msg.type);
  console.log('Data:', JSON.stringify(msg, null, 2));
  console.log('================================\n');

  // If we got a playbook, decision, or advisory, show it and exit
  if (msg.type === 'playbook' || msg.type === 'decision' || msg.type === 'advisory' ||
      msg.type === 'execute_playbook' || msg.type === 'diagnostic_request') {
    console.log('\n*** Received actionable response from server! ***\n');
    setTimeout(() => {
      console.log('Test complete, closing connection');
      ws.close();
      process.exit(0);
    }, 2000);
  }
});

ws.on('error', (err) => {
  console.error('WebSocket error:', err.message);
});

ws.on('close', () => {
  console.log('Connection closed');
});

// Timeout after 2 minutes
setTimeout(() => {
  console.log(`\nTimeout after 2 minutes - received ${messageCount} messages`);
  ws.close();
  process.exit(0);
}, 120000);
