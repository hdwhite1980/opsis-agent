export interface PlaybookStep {
  step_number: number;
  action: string;
  primitive: string;
  params: any;
  verify_success?: string;
  rollback_on_failure?: boolean;
}

export interface Playbook {
  playbook_id: string;
  name: string;
  version: string;
  risk_class: 'A' | 'B' | 'C';
  description: string;
  preconditions?: string[];
  steps: PlaybookStep[];
  verification_steps: string[];
  rollback_steps?: PlaybookStep[];
  estimated_duration_ms: number;
  user_impact: 'none' | 'app_restart' | 'brief_disconnect' | 'service_restart' | 'reboot';
}

export const PLAYBOOK_LIBRARY: { [key: string]: Playbook } = {
  
  // ========================================
  // SERVICE MANAGEMENT PLAYBOOKS
  // ========================================
  
  'service_restart_generic': {
    playbook_id: 'service_restart_generic',
    name: 'Restart Windows Service',
    version: '1.0.0',
    risk_class: 'A',
    description: 'Restart a stopped Windows service',
    steps: [{
      step_number: 1,
      action: 'Restart service',
      primitive: 'restartService',
      params: { serviceName: '{{serviceName}}' }
    }],
    verification_steps: ['Verify service is running'],
    estimated_duration_ms: 10000,
    user_impact: 'service_restart'
  },
  
  'service_start_generic': {
    playbook_id: 'service_start_generic',
    name: 'Start Windows Service',
    version: '1.0.0',
    risk_class: 'A',
    description: 'Start a stopped Windows service',
    steps: [{
      step_number: 1,
      action: 'Start service',
      primitive: 'startService',
      params: { serviceName: '{{serviceName}}' }
    }],
    verification_steps: ['Verify service is running'],
    estimated_duration_ms: 5000,
    user_impact: 'service_restart'
  },
  
  // ========================================
  // PROCESS MANAGEMENT PLAYBOOKS
  // ========================================
  
  'process_kill_by_name': {
    playbook_id: 'process_kill_by_name',
    name: 'Kill Process by Name',
    version: '1.0.0',
    risk_class: 'B',
    description: 'Terminate a CPU-hogging process',
    steps: [{
      step_number: 1,
      action: 'Terminate process',
      primitive: 'killProcessByName',
      params: { processName: '{{processName}}' }
    }],
    verification_steps: ['Verify process terminated', 'Verify CPU decreased'],
    estimated_duration_ms: 5000,
    user_impact: 'app_restart'
  },
  
  'process_restart_by_name': {
    playbook_id: 'process_restart_by_name',
    name: 'Restart Process',
    version: '1.0.0',
    risk_class: 'B',
    description: 'Kill and restart a process',
    steps: [
      {
        step_number: 1,
        action: 'Kill process',
        primitive: 'killProcessByName',
        params: { processName: '{{processName}}' }
      },
      {
        step_number: 2,
        action: 'Wait 3 seconds',
        primitive: 'sleepPrimitive',
        params: { milliseconds: 3000 }
      },
      {
        step_number: 3,
        action: 'Start process',
        primitive: 'startProcess',
        params: { processPath: '{{processPath}}' }
      }
    ],
    verification_steps: ['Verify process is running'],
    estimated_duration_ms: 15000,
    user_impact: 'app_restart'
  },
  
  // ========================================
  // DISK CLEANUP PLAYBOOKS
  // ========================================
  
  'disk_cleanup_comprehensive': {
    playbook_id: 'disk_cleanup_comprehensive',
    name: 'Comprehensive Disk Cleanup',
    version: '1.0.0',
    risk_class: 'A',
    description: 'Full disk cleanup (temp + recycle bin + Windows Update cache)',
    steps: [
      {
        step_number: 1,
        action: 'Clean temp files',
        primitive: 'cleanTempFiles',
        params: {}
      },
      {
        step_number: 2,
        action: 'Empty recycle bin',
        primitive: 'emptyRecycleBin',
        params: {}
      },
      {
        step_number: 3,
        action: 'Clear Windows Update cache',
        primitive: 'clearWindowsUpdateCache',
        params: {}
      }
    ],
    verification_steps: ['Verify disk space increased'],
    estimated_duration_ms: 180000,
    user_impact: 'none'
  },
  
  'disk_cleanup_temp': {
    playbook_id: 'disk_cleanup_temp',
    name: 'Clean Temporary Files',
    version: '1.0.0',
    risk_class: 'A',
    description: 'Delete temporary files',
    steps: [{
      step_number: 1,
      action: 'Run disk cleanup',
      primitive: 'cleanTempFiles',
      params: {}
    }],
    verification_steps: ['Verify disk space increased'],
    estimated_duration_ms: 60000,
    user_impact: 'none'
  },
  
  'disk_cleanup_recycle_bin': {
    playbook_id: 'disk_cleanup_recycle_bin',
    name: 'Empty Recycle Bin',
    version: '1.0.0',
    risk_class: 'A',
    description: 'Empty recycle bin',
    steps: [{
      step_number: 1,
      action: 'Empty recycle bin',
      primitive: 'emptyRecycleBin',
      params: {}
    }],
    verification_steps: ['Verify disk space increased'],
    estimated_duration_ms: 15000,
    user_impact: 'none'
  },
  
  'disk_cleanup_windows_update': {
    playbook_id: 'disk_cleanup_windows_update',
    name: 'Clear Windows Update Cache',
    version: '1.0.0',
    risk_class: 'B',
    description: 'Clear Windows Update cache',
    steps: [{
      step_number: 1,
      action: 'Clear Windows Update cache',
      primitive: 'clearWindowsUpdateCache',
      params: {}
    }],
    verification_steps: ['Verify Windows Update service is running'],
    estimated_duration_ms: 30000,
    user_impact: 'service_restart'
  },
  
  // ========================================
  // NETWORK TROUBLESHOOTING PLAYBOOKS
  // ========================================
  
  'network_flush_dns': {
    playbook_id: 'network_flush_dns',
    name: 'Flush DNS Cache',
    version: '1.0.0',
    risk_class: 'A',
    description: 'Clear DNS resolver cache',
    steps: [{
      step_number: 1,
      action: 'Flush DNS',
      primitive: 'flushDNS',
      params: {}
    }],
    verification_steps: ['Verify DNS cache is empty'],
    estimated_duration_ms: 2000,
    user_impact: 'brief_disconnect'
  },
  
  'network_reset_adapter': {
    playbook_id: 'network_reset_adapter',
    name: 'Reset Network Adapter',
    version: '1.0.0',
    risk_class: 'B',
    description: 'Disable and re-enable network adapter',
    steps: [
      {
        step_number: 1,
        action: 'Disable adapter',
        primitive: 'disableNetworkAdapter',
        params: { adapterName: '{{adapterName}}' }
      },
      {
        step_number: 2,
        action: 'Wait 5 seconds',
        primitive: 'sleepPrimitive',
        params: { milliseconds: 5000 }
      },
      {
        step_number: 3,
        action: 'Enable adapter',
        primitive: 'enableNetworkAdapter',
        params: { adapterName: '{{adapterName}}' }
      }
    ],
    verification_steps: ['Verify adapter is connected', 'Verify internet connectivity'],
    estimated_duration_ms: 15000,
    user_impact: 'brief_disconnect'
  },
  
  'network_renew_ip': {
    playbook_id: 'network_renew_ip',
    name: 'Renew IP Address',
    version: '1.0.0',
    risk_class: 'A',
    description: 'Release and renew DHCP lease',
    steps: [
      {
        step_number: 1,
        action: 'Release IP',
        primitive: 'releaseIP',
        params: {}
      },
      {
        step_number: 2,
        action: 'Renew IP',
        primitive: 'renewIP',
        params: {}
      }
    ],
    verification_steps: ['Verify IP address obtained'],
    estimated_duration_ms: 10000,
    user_impact: 'brief_disconnect'
  },
  
  'network_full_reset': {
    playbook_id: 'network_full_reset',
    name: 'Full Network Reset',
    version: '1.0.0',
    risk_class: 'B',
    description: 'Comprehensive network troubleshooting',
    steps: [
      {
        step_number: 1,
        action: 'Flush DNS',
        primitive: 'flushDNS',
        params: {}
      },
      {
        step_number: 2,
        action: 'Release IP',
        primitive: 'releaseIP',
        params: {}
      },
      {
        step_number: 3,
        action: 'Renew IP',
        primitive: 'renewIP',
        params: {}
      },
      {
        step_number: 4,
        action: 'Restart DHCP Client',
        primitive: 'restartService',
        params: { serviceName: 'Dhcp' }
      }
    ],
    verification_steps: ['Verify internet connectivity', 'Verify DNS resolution'],
    estimated_duration_ms: 30000,
    user_impact: 'brief_disconnect'
  }
};
