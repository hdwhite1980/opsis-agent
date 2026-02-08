/**
 * Test Pre-Escalation Troubleshooting
 * Sends a test escalation through the agent's IPC server to trigger troubleshooting
 *
 * Usage: node test-troubleshooting.js [type]
 * Types: high-cpu, disk-space-low, service-stopped, high-memory, network-issue
 */

const net = require('net');

const IPC_PORT = 19847;
const issueType = process.argv[2] || 'high-cpu';

console.log('\n=== OPSIS Pre-Escalation Troubleshooting Test ===');
console.log(`Issue Type: ${issueType}`);
console.log(`IPC Port: ${IPC_PORT}\n`);

const client = new net.Socket();

client.connect(IPC_PORT, '127.0.0.1', () => {
  console.log('Connected to agent IPC server');

  // Send test-escalation message
  const message = JSON.stringify({
    type: 'test-escalation',
    data: {
      type: issueType,
      severity: 'high',
      confidence: 65
    }
  });

  console.log(`\nSending test escalation: ${issueType}`);
  console.log('The agent will:');
  console.log('  1. Generate a test signature');
  console.log('  2. Run the appropriate troubleshooting runbook');
  console.log('  3. Collect diagnostic data');
  console.log('  4. Send escalation to server with diagnostic_data attached\n');

  client.write(message + '\n');
});

client.on('data', (data) => {
  try {
    const response = JSON.parse(data.toString().trim());
    console.log('=== Agent Response ===');
    console.log(JSON.stringify(response, null, 2));
    console.log('======================\n');
  } catch (e) {
    console.log('Raw response:', data.toString());
  }

  // Give time for the escalation to complete, then disconnect
  setTimeout(() => {
    console.log('Test complete. Check agent logs for troubleshooting details.');
    console.log('Log location: C:\\opsis-agent\\logs\\opsis-agent.log');
    client.destroy();
  }, 2000);
});

client.on('error', (err) => {
  if (err.code === 'ECONNREFUSED') {
    console.error('ERROR: Could not connect to agent IPC server.');
    console.error('Make sure the OPSIS Agent Service is running.');
    console.error('\nTo start the agent:');
    console.error('  npm run start:service');
    console.error('  OR');
    console.error('  node dist/service/agent-service.js');
  } else {
    console.error('Connection error:', err.message);
  }
  process.exit(1);
});

client.on('close', () => {
  console.log('Connection closed');
  process.exit(0);
});

// Timeout after 30 seconds
setTimeout(() => {
  console.log('\nTimeout - closing connection');
  client.destroy();
  process.exit(0);
}, 30000);
