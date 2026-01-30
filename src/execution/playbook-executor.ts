import Logger from '../core/logger';
import { PLAYBOOK_LIBRARY, Playbook, PlaybookStep } from './playbooks/library';
import { Primitives, PrimitiveResult } from './primitives';

export interface ExecutionResult {
  success: boolean;
  playbook_id: string;
  steps_completed: number;
  total_steps: number;
  duration_ms: number;
  verification_passed: boolean;
  error?: string;
  step_results: StepResult[];
}

export interface StepResult {
  step_number: number;
  action: string;
  primitive: string;
  success: boolean;
  duration_ms: number;
  output?: string;
  error?: string;
}

export class PlaybookExecutor {
  private logger: Logger;
  private primitives: Primitives;
  
  constructor(logger: Logger) {
    this.logger = logger;
    this.primitives = new Primitives(logger);
  }
  
  async executePlaybook(playbookId: string, params: any = {}): Promise<ExecutionResult> {
    const startTime = Date.now();
    
    // Load playbook
    const playbook = PLAYBOOK_LIBRARY[playbookId];
    if (!playbook) {
      return {
        success: false,
        playbook_id: playbookId,
        steps_completed: 0,
        total_steps: 0,
        duration_ms: Date.now() - startTime,
        verification_passed: false,
        error: `Playbook not found: ${playbookId}`,
        step_results: []
      };
    }
    
    this.logger.info(`Executing playbook: ${playbook.name}`, { params });
    
    const stepResults: StepResult[] = [];
    let stepsCompleted = 0;
    
    // Execute each step
    for (const step of playbook.steps) {
      this.logger.info(`Step ${step.step_number}: ${step.action}`);
      
      try {
        // Resolve parameters
        const resolvedParams = this.resolveParams(step.params, params);
        
        // Execute primitive
        const result = await this.executePrimitive(step.primitive, resolvedParams);
        
        stepResults.push({
          step_number: step.step_number,
          action: step.action,
          primitive: step.primitive,
          success: result.success,
          duration_ms: result.duration_ms,
          output: result.output,
          error: result.error
        });
        
        if (!result.success) {
          this.logger.error(`Step ${step.step_number} failed`, { error: result.error });
          
          // Execute rollback if needed
          if (step.rollback_on_failure && playbook.rollback_steps) {
            this.logger.warn('Executing rollback steps...');
            await this.executeRollback(playbook.rollback_steps, params);
          }
          
          return {
            success: false,
            playbook_id: playbookId,
            steps_completed: stepsCompleted,
            total_steps: playbook.steps.length,
            duration_ms: Date.now() - startTime,
            verification_passed: false,
            error: `Step ${step.step_number} failed: ${result.error}`,
            step_results: stepResults
          };
        }
        
        stepsCompleted++;
        this.logger.info(`Step ${step.step_number} completed`, { duration_ms: result.duration_ms });
        
      } catch (error: any) {
        this.logger.error(`Step ${step.step_number} exception`, { error: error.message });
        
        stepResults.push({
          step_number: step.step_number,
          action: step.action,
          primitive: step.primitive,
          success: false,
          duration_ms: 0,
          error: error.message
        });
        
        return {
          success: false,
          playbook_id: playbookId,
          steps_completed: stepsCompleted,
          total_steps: playbook.steps.length,
          duration_ms: Date.now() - startTime,
          verification_passed: false,
          error: `Step ${step.step_number} exception: ${error.message}`,
          step_results: stepResults
        };
      }
    }
    
    // All steps completed successfully
    const verificationPassed = await this.runVerification(playbook, params);
    
    return {
      success: true,
      playbook_id: playbookId,
      steps_completed: stepsCompleted,
      total_steps: playbook.steps.length,
      duration_ms: Date.now() - startTime,
      verification_passed: verificationPassed,
      step_results: stepResults
    };
  }
  
  private async executePrimitive(primitive: string, params: any): Promise<PrimitiveResult> {
    switch (primitive) {
      // Process management
      case 'killProcessByName':
        return this.primitives.killProcessByName(params.processName);
      case 'killProcessByPID':
        return this.primitives.killProcessByPID(params.pid);
      case 'startProcess':
        return this.primitives.startProcess(params.processPath, params.args);
      
      // Service management
      case 'restartService':
        return this.primitives.restartService(params.serviceName);
      case 'startService':
        return this.primitives.startService(params.serviceName);
      case 'stopService':
        return this.primitives.stopService(params.serviceName);
      
      // Disk management
      case 'cleanTempFiles':
        return this.primitives.cleanTempFiles();
      case 'emptyRecycleBin':
        return this.primitives.emptyRecycleBin();
      case 'clearWindowsUpdateCache':
        return this.primitives.clearWindowsUpdateCache();
      
      // Network operations
      case 'flushDNS':
        return this.primitives.flushDNS();
      case 'releaseIP':
        return this.primitives.releaseIP();
      case 'renewIP':
        return this.primitives.renewIP();
      case 'disableNetworkAdapter':
        return this.primitives.disableNetworkAdapter(params.adapterName);
      case 'enableNetworkAdapter':
        return this.primitives.enableNetworkAdapter(params.adapterName);
      
      // Registry operations
      case 'setRegistryValue':
        return this.primitives.setRegistryValue(params.key, params.valueName, params.valueData, params.valueType);
      case 'deleteRegistryValue':
        return this.primitives.deleteRegistryValue(params.key, params.valueName);
      
      // File operations
      case 'deleteFile':
        return this.primitives.deleteFile(params.filePath);
      case 'copyFile':
        return this.primitives.copyFile(params.source, params.destination);
      
      // Utilities
      case 'sleepPrimitive':
        return this.primitives.sleepPrimitive(params.milliseconds);
      
      default:
        return {
          success: false,
          error: `Unknown primitive: ${primitive}`,
          duration_ms: 0
        };
    }
  }
  
  private resolveParams(stepParams: any, executionParams: any): any {
    const resolved: any = {};
    
    for (const [key, value] of Object.entries(stepParams)) {
      if (typeof value === 'string' && value.includes('{{') && value.includes('}}')) {
        // Template variable
        const match = value.match(/\{\{([^}]+)\}\}/);
        if (match) {
          const varName = match[1].trim();
          resolved[key] = executionParams[varName] || value;
        }
      } else {
        resolved[key] = value;
      }
    }
    
    return resolved;
  }
  
  private async runVerification(playbook: Playbook, params: any): Promise<boolean> {
    // Simple verification for now - can be enhanced later
    for (const verification of playbook.verification_steps) {
      this.logger.info(`Verification: ${verification}`);
      
      // Example verification logic
      if (verification.includes('Verify service is running')) {
        if (params.serviceName) {
          const isRunning = await this.primitives.serviceIsRunning(params.serviceName);
          if (!isRunning) {
            this.logger.warn(`Verification failed: Service ${params.serviceName} is not running`);
            return false;
          }
        }
      }
      
      if (verification.includes('Verify process terminated')) {
        if (params.processName) {
          const exists = await this.primitives.processExists(params.processName);
          if (exists) {
            this.logger.warn(`Verification failed: Process ${params.processName} still exists`);
            return false;
          }
        }
      }
    }
    
    return true;
  }
  
  private async executeRollback(rollbackSteps: PlaybookStep[], params: any): Promise<void> {
    this.logger.warn('Executing rollback...');
    
    for (const step of rollbackSteps) {
      try {
        const resolvedParams = this.resolveParams(step.params, params);
        const result = await this.executePrimitive(step.primitive, resolvedParams);
        
        if (!result.success) {
          this.logger.error(`Rollback step ${step.step_number} failed`, { error: result.error });
        } else {
          this.logger.info(`Rollback step ${step.step_number} completed`);
        }
      } catch (error: any) {
        this.logger.error(`Rollback step ${step.step_number} exception`, { error: error.message });
      }
    }
  }
  
  getAvailablePlaybooks(): string[] {
    return Object.keys(PLAYBOOK_LIBRARY);
  }
  
  getPlaybookInfo(playbookId: string): Playbook | undefined {
    return PLAYBOOK_LIBRARY[playbookId];
  }
}
