/**
 * Standalone Test for Pre-Escalation Troubleshooting
 * Tests the TroubleshootingRunner directly without needing the agent service
 *
 * Usage: node test-troubleshooting-standalone.js [category]
 * Categories: cpu, memory, disk, service, network, general
 */

const path = require('path');

// Load the compiled modules
const { TroubleshootingRunner } = require('./dist/service/troubleshooting-runner');
const { Logger } = require('./dist/common/logger');

const category = process.argv[2] || 'cpu';
const dataDir = path.join(__dirname, 'data');

console.log('\n=== OPSIS Troubleshooting Runner Standalone Test ===');
console.log(`Category: ${category}`);
console.log(`Data Dir: ${dataDir}\n`);

// Create a simple console logger
const logger = {
  info: (msg, data) => console.log(`[INFO] ${msg}`, data ? JSON.stringify(data) : ''),
  warn: (msg, data) => console.log(`[WARN] ${msg}`, data ? JSON.stringify(data) : ''),
  error: (msg, data) => console.log(`[ERROR] ${msg}`, data ? JSON.stringify(data) : ''),
  debug: (msg, data) => {} // Suppress debug
};

// Create a mock signature based on category
function createMockSignature(category) {
  const base = {
    signature_id: `test-${Date.now()}`,
    tenant_id: 'test-tenant',
    device_id: 'test-device',
    timestamp: new Date().toISOString(),
    severity: 'high',
    confidence_local: 65,
    symptoms: [],
    targets: [],
    context: {
      os_build: '22631',
      os_version: 'Windows 11'
    }
  };

  switch (category) {
    case 'cpu':
      base.symptoms = [{
        type: 'performance',
        severity: 'high',
        details: { metric: 'cpu_usage', value: 95, threshold: 80, process_name: 'test.exe' }
      }];
      base.targets = [{ type: 'process', name: 'test.exe', identifier: '1234' }];
      break;

    case 'memory':
      base.symptoms = [{
        type: 'performance',
        severity: 'high',
        details: { metric: 'memory_usage', value: 92, threshold: 85 }
      }];
      break;

    case 'disk':
      base.symptoms = [{
        type: 'disk',
        severity: 'high',
        details: { drive: 'C:', free_percent: 5, free_gb: 12 }
      }];
      break;

    case 'service':
      base.symptoms = [{
        type: 'service_status',
        severity: 'high',
        details: { service: 'Spooler', state: 'Stopped' }
      }];
      base.targets = [{ type: 'service', name: 'Spooler', identifier: 'spooler' }];
      break;

    case 'network':
      base.symptoms = [{
        type: 'network',
        severity: 'high',
        details: { issue: 'connectivity_lost' }
      }];
      break;

    case 'general':
    default:
      base.symptoms = [{
        type: 'event_log',
        severity: 'high',
        details: { source: 'Application', event_id: 1000 }
      }];
      break;
  }

  return base;
}

async function runTest() {
  console.log('Initializing TroubleshootingRunner...\n');

  const runner = new TroubleshootingRunner(logger, dataDir);

  console.log('Available categories:', runner.getAvailableCategories());
  console.log('');

  // Create mock signature
  const signature = createMockSignature(category);
  console.log('Mock Signature:');
  console.log(JSON.stringify(signature, null, 2));
  console.log('');

  // Classify the issue
  const detectedCategory = runner.classifyIssue(signature);
  console.log(`Detected Category: ${detectedCategory}`);

  // Get the runbook
  const runbook = runner.getRunbook(detectedCategory);
  if (runbook) {
    console.log(`Runbook: ${runbook.id} (${runbook.steps.length} steps)`);
    console.log(`Steps: ${runbook.steps.map(s => s.primitive).join(', ')}`);
  }
  console.log('');

  // Run troubleshooting
  console.log('Running troubleshooting (15 second timeout)...\n');
  const startTime = Date.now();

  try {
    const diagnosticData = await runner.runTroubleshooting(signature, 15000);

    if (diagnosticData) {
      console.log('=== DIAGNOSTIC DATA COLLECTED ===\n');
      console.log(`Runbook ID: ${diagnosticData.runbook_id}`);
      console.log(`Category: ${diagnosticData.category}`);
      console.log(`Duration: ${diagnosticData.duration_ms}ms`);
      console.log(`Partial Failure: ${diagnosticData.partial_failure}`);

      if (diagnosticData.errors && diagnosticData.errors.length > 0) {
        console.log(`Errors: ${diagnosticData.errors.join(', ')}`);
      }

      console.log(`\nData Keys: ${Object.keys(diagnosticData.data).join(', ')}`);
      console.log('');

      // Print each result
      for (const [key, result] of Object.entries(diagnosticData.data)) {
        console.log(`--- ${key} ---`);
        console.log(`  Success: ${result.success}`);
        console.log(`  Duration: ${result.duration_ms}ms`);

        if (result.error) {
          console.log(`  Error: ${result.error}`);
        }

        if (result.data) {
          // Truncate large data for display
          const dataStr = JSON.stringify(result.data, null, 2);
          if (dataStr.length > 1000) {
            console.log(`  Data: ${dataStr.substring(0, 1000)}... (truncated)`);
          } else {
            console.log(`  Data: ${dataStr}`);
          }
        }
        console.log('');
      }

      console.log('=================================\n');

      // Show what would be sent to server
      console.log('This diagnostic_data would be attached to the escalation payload.');
      console.log(`Total collection time: ${Date.now() - startTime}ms`);

    } else {
      console.log('No diagnostic data returned');
    }

  } catch (error) {
    console.error('Troubleshooting failed:', error.message);
  }
}

runTest().catch(console.error);
