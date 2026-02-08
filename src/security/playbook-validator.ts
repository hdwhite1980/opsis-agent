/**
 * OPSIS Agent Playbook Validator
 * Validates playbook structure and step types before execution
 */

// Allowed step types - must match server's allowed types
const ALLOWED_STEP_TYPES = new Set([
  'powershell',
  'cmd',
  'restart_service',
  'kill_process',
  'clear_temp',
  'check_disk',
  'check_service',
  'registry_read',
  'registry_write',
  'file_check',
  'file_delete',
  'event_log_query',
  // Also allow primitives used by local runbooks
  'diagnostic',
  'service',
  'process',
  'network',
  'disk',
  'system',
  'sleep'
]);

// Shell metacharacters that indicate injection attempts (extended)
// Covers: command substitution, chaining, redirection, quoting, escapes
const SHELL_METACHARACTERS = /[`$()&|;<>!\n\r\x00\x1a"'^]/;

// Additional dangerous patterns for both CMD and PowerShell
const DANGEROUS_PATTERNS = [
  /\$\(/,                     // PowerShell command substitution
  /`.*`/,                     // Backtick command substitution
  /&&/,                       // Command chaining (AND)
  /\|\|/,                     // Command chaining (OR)
  /;/,                        // Command separator
  /\|/,                       // Pipe
  />>/,                       // Append redirect
  />/,                        // Redirect output
  /</,                        // Redirect input
  /2>&1/,                     // Redirect stderr to stdout
  /\n/,                       // Newline
  /\r/,                       // Carriage return
  /\x00/,                     // Null byte injection
  /\x1a/,                     // Ctrl+Z (EOF in Windows)
  /%[a-zA-Z_][a-zA-Z0-9_]*%/, // Windows environment variable expansion
  /\$env:/i,                  // PowerShell env variable
  /\$\{/,                     // PowerShell variable with braces
  /\$\[/,                     // PowerShell array indexing
  /\.\s*\(/,                  // PowerShell dot-sourcing method call
  /\:\:/,                     // PowerShell static method call
  /\[.*\]\s*::/,              // PowerShell type accelerator
  /-[a-z]+\s+\{/i,            // PowerShell script block parameter
  /invoke-expression/i,       // Dangerous PowerShell cmdlet
  /iex\s/i,                   // IEX alias
  /invoke-command/i,          // Remote execution
  /start-process/i,           // Process spawning
  /new-object/i,              // Object creation (can be abused)
  /downloadstring/i,          // Web download methods
  /downloadfile/i,            // File download methods
  /\.\.[\\/]/,                // Path traversal
  /^\s*\//,                   // Leading slash (Unix path injection)
];

export interface PlaybookStep {
  type?: string;
  primitive?: string;
  action?: string;
  command?: string;
  script?: string;
  params?: Record<string, any>;
}

export interface Playbook {
  id?: string;
  playbook_id?: string;
  name?: string;
  steps?: PlaybookStep[];
  _signature?: string;
  _timestamp?: string;
}

export interface ValidationResult {
  valid: boolean;
  errors: string[];
}

/**
 * Validate a playbook structure and content
 */
export function validatePlaybook(playbook: any): ValidationResult {
  const errors: string[] = [];

  // Must be an object
  if (!playbook || typeof playbook !== 'object') {
    return { valid: false, errors: ['Playbook must be an object'] };
  }

  // Must have an ID
  const playbookId = playbook.id || playbook.playbook_id;
  if (!playbookId || typeof playbookId !== 'string') {
    errors.push('Playbook must have a valid id or playbook_id');
  } else {
    // Validate ID format
    if (!/^[a-zA-Z0-9\-_]+$/.test(playbookId)) {
      errors.push('Playbook ID contains invalid characters');
    }
  }

  // Validate steps array
  if (!Array.isArray(playbook.steps)) {
    errors.push('Playbook must have a steps array');
  } else {
    // Validate each step
    playbook.steps.forEach((step: any, index: number) => {
      const stepErrors = validateStep(step, index);
      errors.push(...stepErrors);
    });
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Validate a single playbook step
 */
export function validateStep(step: any, index: number): string[] {
  const errors: string[] = [];
  const prefix = `Step ${index + 1}`;

  if (!step || typeof step !== 'object') {
    errors.push(`${prefix}: must be an object`);
    return errors;
  }

  // Get the step type
  const stepType = step.type || step.primitive;

  if (!stepType) {
    errors.push(`${prefix}: must have a type or primitive`);
    return errors;
  }

  // Validate step type is allowed
  if (!ALLOWED_STEP_TYPES.has(stepType)) {
    errors.push(`${prefix}: disallowed step type '${stepType}'`);
    return errors;
  }

  // Validate command/script content if present
  if (step.command) {
    const cmdErrors = validateCommand(step.command, `${prefix} command`);
    errors.push(...cmdErrors);
  }

  if (step.script) {
    const scriptErrors = validateCommand(step.script, `${prefix} script`);
    errors.push(...scriptErrors);
  }

  // Validate params
  if (step.params) {
    if (typeof step.params !== 'object') {
      errors.push(`${prefix}: params must be an object`);
    } else {
      // Check each param value for dangerous content
      for (const [key, value] of Object.entries(step.params)) {
        if (typeof value === 'string') {
          const paramErrors = validateParamValue(value, `${prefix} param '${key}'`);
          errors.push(...paramErrors);
        }
      }
    }
  }

  return errors;
}

/**
 * Validate a command string for shell metacharacters
 */
export function validateCommand(command: any, context: string): string[] {
  const errors: string[] = [];

  if (typeof command !== 'string') {
    errors.push(`${context}: must be a string`);
    return errors;
  }

  // Check for shell metacharacters
  if (SHELL_METACHARACTERS.test(command)) {
    errors.push(`${context}: contains shell metacharacters`);
  }

  // Check for dangerous patterns
  for (const pattern of DANGEROUS_PATTERNS) {
    if (pattern.test(command)) {
      errors.push(`${context}: contains dangerous pattern`);
      break;
    }
  }

  return errors;
}

/**
 * Validate a parameter value
 */
export function validateParamValue(value: string, context: string): string[] {
  const errors: string[] = [];

  // Check for shell metacharacters in param values
  if (SHELL_METACHARACTERS.test(value)) {
    errors.push(`${context}: contains shell metacharacters`);
  }

  // Check for command injection patterns
  for (const pattern of DANGEROUS_PATTERNS) {
    if (pattern.test(value)) {
      errors.push(`${context}: contains dangerous pattern`);
      break;
    }
  }

  return errors;
}

// Dangerous patterns for diagnostic commands (much less restrictive than playbook validation).
// Diagnostic requests are HMAC-authenticated, so the server is trusted.
// Only block patterns that indicate code injection or remote code download.
const DIAGNOSTIC_DANGEROUS_PATTERNS = [
  /invoke-expression/i,       // Arbitrary code execution
  /\biex\s/i,                 // IEX alias
  /downloadstring/i,          // Web download methods
  /downloadfile/i,            // File download methods
  /invoke-webrequest/i,       // Web requests that could download payloads
  /start-bitstransfer/i,      // BITS download
  /\x00/,                     // Null byte injection
  /\x1a/,                     // Ctrl+Z (EOF in Windows)
  /\.\.[\\/].*\.\.[\\/]/,     // Deep path traversal (2+ levels)
];

/**
 * Validate a diagnostic request.
 * Diagnostic commands are HMAC-signed by the server, so we only perform
 * structural validation and block obvious code-injection patterns.
 * Normal PowerShell syntax (pipes, variables, subexpressions) is allowed.
 */
export function validateDiagnosticRequest(request: any): ValidationResult {
  const errors: string[] = [];

  if (!request || typeof request !== 'object') {
    return { valid: false, errors: ['Diagnostic request must be an object'] };
  }

  // Validate session_id if present
  if (request.session_id && typeof request.session_id === 'string') {
    if (!/^[a-zA-Z0-9\-_]+$/.test(request.session_id)) {
      errors.push('Invalid session_id format');
    }
  }

  // Validate commands array if present
  if (request.commands) {
    if (!Array.isArray(request.commands)) {
      errors.push('commands must be an array');
    } else {
      request.commands.forEach((cmd: any, index: number) => {
        const cmdStr = typeof cmd === 'string' ? cmd : cmd?.command;
        if (typeof cmdStr === 'string') {
          for (const pattern of DIAGNOSTIC_DANGEROUS_PATTERNS) {
            if (pattern.test(cmdStr)) {
              errors.push(`Command ${index + 1}: contains blocked pattern`);
              break;
            }
          }
        }
      });
    }
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Check if a step type is allowed
 */
export function isAllowedStepType(stepType: string): boolean {
  return ALLOWED_STEP_TYPES.has(stepType);
}

/**
 * Get list of allowed step types
 */
export function getAllowedStepTypes(): string[] {
  return Array.from(ALLOWED_STEP_TYPES);
}
