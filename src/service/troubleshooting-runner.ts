/**
 * OPSIS Agent Troubleshooting Runner
 * Runs pre-escalation diagnostic runbooks to collect rich data before escalating to server
 */

import { Logger } from '../common/logger';
import { Primitives, DiagnosticResult } from '../execution/primitives';
import { DeviceSignature } from './signature-generator';
import * as fs from 'fs';
import * as path from 'path';
import { verifyRunbookIntegrity, registerRunbookHash } from '../security';

// Issue categories for routing to troubleshooting runbooks
export type IssueCategory = 'cpu' | 'memory' | 'disk' | 'service' | 'network' | 'general';

export interface TroubleshootingStep {
  step_number: number;
  primitive: string;
  params: Record<string, any>;
  output_key: string;
}

export interface TroubleshootingRunbook {
  id: string;
  name: string;
  description: string;
  category: IssueCategory;
  timeout_ms: number;
  steps: TroubleshootingStep[];
}

export interface DiagnosticData {
  runbook_id: string;
  category: IssueCategory;
  collected_at: string;
  duration_ms: number;
  data: Record<string, DiagnosticResult>;
  partial_failure: boolean;
  errors?: string[];
}

// Default troubleshooting runbooks embedded in code
const DEFAULT_RUNBOOKS: TroubleshootingRunbook[] = [
  {
    id: 'cpu_troubleshoot',
    name: 'CPU Troubleshooting',
    description: 'Collect diagnostic data for high CPU issues',
    category: 'cpu',
    timeout_ms: 15000,
    steps: [
      { step_number: 1, primitive: 'getTopProcesses', params: { count: 15 }, output_key: 'top_processes' },
      { step_number: 2, primitive: 'getProcessorDetails', params: {}, output_key: 'processor_info' },
      { step_number: 3, primitive: 'getRecentInstalls', params: { days: 7 }, output_key: 'recent_installs' }
    ]
  },
  {
    id: 'service_troubleshoot',
    name: 'Service Troubleshooting',
    description: 'Collect diagnostic data for service issues',
    category: 'service',
    timeout_ms: 15000,
    steps: [
      { step_number: 1, primitive: 'getServiceDetails', params: { serviceName: '{{target_service}}' }, output_key: 'service_details' },
      { step_number: 2, primitive: 'getServiceEventLogs', params: { serviceName: '{{target_service}}', hours: 24 }, output_key: 'service_events' },
      { step_number: 3, primitive: 'getFailedServices', params: {}, output_key: 'all_failed_services' }
    ]
  },
  {
    id: 'disk_troubleshoot',
    name: 'Disk Troubleshooting',
    description: 'Collect diagnostic data for disk issues',
    category: 'disk',
    timeout_ms: 15000,
    steps: [
      { step_number: 1, primitive: 'getDiskUsage', params: {}, output_key: 'disk_usage' },
      { step_number: 2, primitive: 'getLargestFolders', params: { drive: '{{target_drive}}', topN: 10 }, output_key: 'largest_folders' },
      { step_number: 3, primitive: 'getRecentFileGrowth', params: { drive: '{{target_drive}}', hours: 24 }, output_key: 'recent_growth' },
      { step_number: 4, primitive: 'getSMARTData', params: {}, output_key: 'smart_data' }
    ]
  },
  {
    id: 'memory_troubleshoot',
    name: 'Memory Troubleshooting',
    description: 'Collect diagnostic data for memory issues',
    category: 'memory',
    timeout_ms: 15000,
    steps: [
      { step_number: 1, primitive: 'getMemoryConsumers', params: { topN: 15 }, output_key: 'top_memory_consumers' },
      { step_number: 2, primitive: 'getPageFileStatus', params: {}, output_key: 'page_file_status' },
      { step_number: 3, primitive: 'getSystemMemoryDetails', params: {}, output_key: 'system_memory' }
    ]
  },
  {
    id: 'network_troubleshoot',
    name: 'Network Troubleshooting',
    description: 'Collect diagnostic data for network issues',
    category: 'network',
    timeout_ms: 15000,
    steps: [
      { step_number: 1, primitive: 'getNetworkAdapters', params: {}, output_key: 'network_adapters' },
      { step_number: 2, primitive: 'getDNSResolutionTest', params: { hosts: ['google.com', 'microsoft.com', 'cloudflare.com'] }, output_key: 'dns_tests' },
      { step_number: 3, primitive: 'getRouteTable', params: {}, output_key: 'route_table' },
      { step_number: 4, primitive: 'getConnectivityTest', params: { endpoints: ['https://www.google.com', 'https://www.microsoft.com'] }, output_key: 'connectivity_tests' }
    ]
  },
  {
    id: 'general_troubleshoot',
    name: 'General Troubleshooting',
    description: 'Baseline system snapshot for uncategorized issues',
    category: 'general',
    timeout_ms: 15000,
    steps: [
      { step_number: 1, primitive: 'getSystemSnapshot', params: {}, output_key: 'system_snapshot' },
      { step_number: 2, primitive: 'getRecentEventLogErrors', params: { hours: 24 }, output_key: 'recent_errors' },
      { step_number: 3, primitive: 'getFailedServices', params: {}, output_key: 'failed_services' },
      { step_number: 4, primitive: 'getDiskUsage', params: {}, output_key: 'disk_usage' }
    ]
  }
];

export class TroubleshootingRunner {
  private logger: Logger;
  private primitives: Primitives;
  private runbooks: Map<IssueCategory, TroubleshootingRunbook>;
  private dataDir: string;

  constructor(logger: Logger, dataDir: string) {
    this.logger = logger;
    this.dataDir = dataDir;
    this.primitives = new Primitives(logger);
    this.runbooks = new Map();
    this.loadRunbooks().catch(err => {
      this.logger.error('Failed to load troubleshooting runbooks', err);
    });
  }

  /**
   * Load runbooks from file or use defaults
   */
  private async loadRunbooks(): Promise<void> {
    const runbookPath = path.join(this.dataDir, 'troubleshooting-runbooks.json');

    try {
      if (fs.existsSync(runbookPath)) {
        const fileContent = fs.readFileSync(runbookPath, 'utf-8');

        // Verify integrity before trusting file contents
        const integrity = await verifyRunbookIntegrity('troubleshooting:runbooks', fileContent);
        if (integrity.reason === 'hash_mismatch') {
          this.logger.error('SECURITY: Troubleshooting runbooks file tampered, using defaults only', {
            expected_hash: integrity.expected_hash,
            actual_hash: integrity.actual_hash,
          });
          // Fall through to load defaults below
        } else {
          if (integrity.reason === 'no_stored_hash') {
            await registerRunbookHash('troubleshooting:runbooks', fileContent);
          }

          const data = JSON.parse(fileContent);
          if (data.runbooks && Array.isArray(data.runbooks)) {
            for (const runbook of data.runbooks) {
              if (this.validateRunbook(runbook)) {
                this.runbooks.set(runbook.category as IssueCategory, runbook);
              }
            }
            this.logger.info('Loaded troubleshooting runbooks from file', { count: this.runbooks.size });
          }
        }
      }
    } catch (error: any) {
      this.logger.warn('Failed to load troubleshooting runbooks from file, using defaults', { error: error.message });
    }

    // Load defaults for any missing categories
    for (const runbook of DEFAULT_RUNBOOKS) {
      if (!this.runbooks.has(runbook.category)) {
        this.runbooks.set(runbook.category, runbook);
      }
    }

    this.logger.info('Troubleshooting runbooks ready', { count: this.runbooks.size });
  }

  /**
   * Validate runbook structure
   */
  private validateRunbook(runbook: any): boolean {
    if (!runbook || typeof runbook !== 'object') return false;
    if (!runbook.id || typeof runbook.id !== 'string') return false;
    if (!runbook.category || !['cpu', 'memory', 'disk', 'service', 'network', 'general'].includes(runbook.category)) return false;
    if (!Array.isArray(runbook.steps) || runbook.steps.length === 0) return false;

    for (const step of runbook.steps) {
      if (!step.primitive || typeof step.primitive !== 'string') return false;
      if (!step.output_key || typeof step.output_key !== 'string') return false;
    }

    return true;
  }

  /**
   * Determine the issue category from a DeviceSignature
   */
  classifyIssue(signature: DeviceSignature): IssueCategory {
    // Priority-based classification based on symptoms
    for (const symptom of signature.symptoms) {
      // Performance symptoms
      if (symptom.type === 'performance') {
        const metric = symptom.details?.metric;
        if (metric === 'cpu_usage' || metric === 'process_cpu') {
          return 'cpu';
        }
        if (metric === 'memory_usage') {
          return 'memory';
        }
      }

      // Service symptoms
      if (symptom.type === 'service_status') {
        return 'service';
      }

      // Disk symptoms
      if (symptom.type === 'disk') {
        return 'disk';
      }

      // Network symptoms
      if (symptom.type === 'network') {
        return 'network';
      }
    }

    // Check targets for additional hints
    for (const target of signature.targets) {
      if (target.type === 'service') {
        return 'service';
      }
      if (target.type === 'process') {
        return 'cpu'; // Process issues often manifest as CPU
      }
      if (target.type === 'network') {
        return 'network';
      }
    }

    // Default to general troubleshooting
    return 'general';
  }

  /**
   * Run the appropriate troubleshooting runbook for a signature
   * Returns diagnostic data to attach to escalation payload
   */
  async runTroubleshooting(
    signature: DeviceSignature,
    timeoutMs: number = 15000
  ): Promise<DiagnosticData | null> {
    const startTime = Date.now();
    const category = this.classifyIssue(signature);
    const runbook = this.runbooks.get(category);

    if (!runbook) {
      this.logger.warn('No troubleshooting runbook for category', { category });
      return null;
    }

    this.logger.info('Running troubleshooting runbook', {
      signature_id: signature.signature_id,
      category,
      runbook_id: runbook.id,
      step_count: runbook.steps.length
    });

    const results: Record<string, DiagnosticResult> = {};
    const errors: string[] = [];
    const effectiveTimeout = Math.min(timeoutMs, runbook.timeout_ms || 15000);

    // Extract parameters from signature for template substitution
    const params = this.extractParamsFromSignature(signature);

    // Track execution with timeout
    let timedOut = false;
    const timeoutId = setTimeout(() => {
      timedOut = true;
    }, effectiveTimeout);

    try {
      for (const step of runbook.steps) {
        // Check if we've timed out
        if (timedOut) {
          this.logger.warn('Troubleshooting timed out', {
            runbook_id: runbook.id,
            steps_completed: Object.keys(results).length,
            total_steps: runbook.steps.length
          });
          errors.push('Timed out before completing all steps');
          break;
        }

        // Check remaining time for this step
        const elapsed = Date.now() - startTime;
        const remaining = effectiveTimeout - elapsed;
        if (remaining < 1000) {
          errors.push('Insufficient time for remaining steps');
          break;
        }

        try {
          // Resolve template parameters
          const resolvedParams = this.resolveParams(step.params, params);

          // Execute diagnostic primitive
          const result = await this.executeDiagnosticPrimitive(step.primitive, resolvedParams);
          results[step.output_key] = result;

          if (!result.success && result.error) {
            errors.push(`${step.primitive}: ${result.error}`);
          }
        } catch (error: any) {
          errors.push(`${step.primitive}: ${error.message}`);
          results[step.output_key] = {
            success: false,
            error: error.message,
            duration_ms: 0,
            collected_at: new Date().toISOString()
          };
        }
      }
    } finally {
      clearTimeout(timeoutId);
    }

    const diagnosticData: DiagnosticData = {
      runbook_id: runbook.id,
      category,
      collected_at: new Date().toISOString(),
      duration_ms: Date.now() - startTime,
      data: results,
      partial_failure: errors.length > 0,
      errors: errors.length > 0 ? errors : undefined
    };

    this.logger.info('Troubleshooting completed', {
      signature_id: signature.signature_id,
      runbook_id: runbook.id,
      steps_completed: Object.keys(results).length,
      total_steps: runbook.steps.length,
      duration_ms: diagnosticData.duration_ms,
      partial_failure: diagnosticData.partial_failure
    });

    return diagnosticData;
  }

  /**
   * Run diagnostics by category directly (for self-service portal).
   * Does not require a DeviceSignature.
   */
  async runByCategory(
    category: IssueCategory,
    params: Record<string, any> = {},
    timeoutMs: number = 20000,
    onProgress?: (step: number, total: number, description: string) => void
  ): Promise<DiagnosticData | null> {
    const startTime = Date.now();
    const runbook = this.runbooks.get(category);

    if (!runbook) {
      this.logger.warn('No troubleshooting runbook for category', { category });
      return null;
    }

    // Apply defaults for missing params
    if (!params.target_drive) params.target_drive = 'C:';
    if (!params.target_service) params.target_service = 'Spooler';

    this.logger.info('Running diagnostics by category', { category, runbook_id: runbook.id });

    const results: Record<string, DiagnosticResult> = {};
    const errors: string[] = [];
    const effectiveTimeout = Math.min(timeoutMs, runbook.timeout_ms || 20000);

    let timedOut = false;
    const timeoutId = setTimeout(() => { timedOut = true; }, effectiveTimeout);

    try {
      for (let i = 0; i < runbook.steps.length; i++) {
        if (timedOut) {
          errors.push('Timed out before completing all steps');
          break;
        }

        const step = runbook.steps[i];

        // Report progress
        if (onProgress) {
          const descriptions: Record<string, string> = {
            getTopProcesses: 'Checking running processes...',
            getProcessorDetails: 'Checking CPU details...',
            getRecentInstalls: 'Checking recent software changes...',
            getServiceDetails: 'Checking service status...',
            getServiceEventLogs: 'Checking service event logs...',
            getFailedServices: 'Checking for stopped services...',
            getDiskUsage: 'Checking disk space...',
            getLargestFolders: 'Analyzing folder sizes...',
            getRecentFileGrowth: 'Checking recent file growth...',
            getSMARTData: 'Checking disk health...',
            getMemoryConsumers: 'Checking memory usage...',
            getPageFileStatus: 'Checking page file...',
            getSystemMemoryDetails: 'Checking system memory...',
            getNetworkAdapters: 'Checking network adapters...',
            getDNSResolutionTest: 'Testing DNS resolution...',
            getRouteTable: 'Checking network routes...',
            getConnectivityTest: 'Testing internet connectivity...',
            getSystemSnapshot: 'Taking system snapshot...',
            getRecentEventLogErrors: 'Checking event logs...'
          };
          onProgress(i + 1, runbook.steps.length, descriptions[step.primitive] || `Running ${step.primitive}...`);
        }

        try {
          const resolvedParams = this.resolveParams(step.params, params);
          const result = await this.executeDiagnosticPrimitive(step.primitive, resolvedParams);
          results[step.output_key] = result;
          if (!result.success && result.error) {
            errors.push(`${step.primitive}: ${result.error}`);
          }
        } catch (error: any) {
          errors.push(`${step.primitive}: ${error.message}`);
          results[step.output_key] = {
            success: false,
            error: error.message,
            duration_ms: 0,
            collected_at: new Date().toISOString()
          };
        }
      }
    } finally {
      clearTimeout(timeoutId);
    }

    return {
      runbook_id: runbook.id,
      category,
      collected_at: new Date().toISOString(),
      duration_ms: Date.now() - startTime,
      data: results,
      partial_failure: errors.length > 0,
      errors: errors.length > 0 ? errors : undefined
    };
  }

  /**
   * Extract parameters from signature for template substitution
   */
  private extractParamsFromSignature(signature: DeviceSignature): Record<string, any> {
    const params: Record<string, any> = {};

    // Extract service name if available
    const serviceTarget = signature.targets.find(t => t.type === 'service');
    if (serviceTarget) {
      params.target_service = serviceTarget.name;
    } else {
      // Try to find service in symptom details
      for (const symptom of signature.symptoms) {
        if (symptom.type === 'service_status' && symptom.details?.service) {
          params.target_service = symptom.details.service;
          break;
        }
      }
    }

    // Extract drive letter if available
    for (const symptom of signature.symptoms) {
      if (symptom.type === 'disk' && symptom.details?.drive) {
        params.target_drive = symptom.details.drive;
        break;
      }
    }

    // Default drive if not found
    if (!params.target_drive) {
      params.target_drive = 'C:';
    }

    // Default service if not found (use a safe fallback)
    if (!params.target_service) {
      params.target_service = 'Spooler'; // Safe service to query
    }

    // Extract process name if available
    const processTarget = signature.targets.find(t => t.type === 'process');
    if (processTarget) {
      params.target_process = processTarget.name;
    }

    return params;
  }

  /**
   * Resolve template parameters in step params
   */
  private resolveParams(
    stepParams: Record<string, any>,
    contextParams: Record<string, any>
  ): Record<string, any> {
    const resolved: Record<string, any> = {};

    for (const [key, value] of Object.entries(stepParams)) {
      if (typeof value === 'string' && value.startsWith('{{') && value.endsWith('}}')) {
        const paramName = value.slice(2, -2);
        resolved[key] = contextParams[paramName] !== undefined ? contextParams[paramName] : value;
      } else if (Array.isArray(value)) {
        // Handle arrays (like hosts list for DNS test)
        resolved[key] = value;
      } else {
        resolved[key] = value;
      }
    }

    return resolved;
  }

  /**
   * Execute a diagnostic primitive by name
   */
  private async executeDiagnosticPrimitive(
    primitive: string,
    params: Record<string, any>
  ): Promise<DiagnosticResult> {
    // Dispatch to the appropriate diagnostic primitive
    switch (primitive) {
      // CPU primitives
      case 'getTopProcesses':
        return this.primitives.getTopProcesses(params.count);
      case 'getProcessorDetails':
        return this.primitives.getProcessorDetails();
      case 'getRecentInstalls':
        return this.primitives.getRecentInstalls(params.days);

      // Service primitives
      case 'getServiceDetails':
        return this.primitives.getServiceDetails(params.serviceName);
      case 'getServiceEventLogs':
        return this.primitives.getServiceEventLogs(params.serviceName, params.hours);
      case 'getFailedServices':
        return this.primitives.getFailedServices();

      // Disk primitives
      case 'getDiskUsage':
        return this.primitives.getDiskUsage();
      case 'getLargestFolders':
        return this.primitives.getLargestFolders(params.drive, params.topN);
      case 'getRecentFileGrowth':
        return this.primitives.getRecentFileGrowth(params.drive, params.hours);
      case 'getSMARTData':
        return this.primitives.getSMARTData();

      // Memory primitives
      case 'getMemoryConsumers':
        return this.primitives.getMemoryConsumers(params.topN);
      case 'getPageFileStatus':
        return this.primitives.getPageFileStatus();
      case 'getSystemMemoryDetails':
        return this.primitives.getSystemMemoryDetails();

      // Network primitives
      case 'getNetworkAdapters':
        return this.primitives.getNetworkAdapters();
      case 'getDNSResolutionTest':
        return this.primitives.getDNSResolutionTest(params.hosts);
      case 'getRouteTable':
        return this.primitives.getRouteTable();
      case 'getConnectivityTest':
        return this.primitives.getConnectivityTest(params.endpoints);

      // General primitives
      case 'getSystemSnapshot':
        return this.primitives.getSystemSnapshot();
      case 'getRecentEventLogErrors':
        return this.primitives.getRecentEventLogErrors(params.hours);

      default:
        return {
          success: false,
          error: `Unknown diagnostic primitive: ${primitive}`,
          duration_ms: 0,
          collected_at: new Date().toISOString()
        };
    }
  }

  /**
   * Get available runbook categories
   */
  getAvailableCategories(): IssueCategory[] {
    return Array.from(this.runbooks.keys());
  }

  /**
   * Get runbook by category
   */
  getRunbook(category: IssueCategory): TroubleshootingRunbook | undefined {
    return this.runbooks.get(category);
  }
}

export default TroubleshootingRunner;
