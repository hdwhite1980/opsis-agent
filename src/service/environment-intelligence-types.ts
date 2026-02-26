// environment-intelligence-types.ts - Type definitions for Environment Intelligence service

// ============================
// HARDWARE
// ============================

export interface CpuInfo {
  model: string;
  cores: number;
  logical_processors: number;
  max_clock_mhz: number;
  architecture: string;
}

export interface MemoryHardwareInfo {
  total_gb: number;
  type: string;           // DDR4, DDR5, Unknown
  speed_mhz: number;
  slots_used: number;
  slots_total: number;
}

export interface PartitionEntry {
  drive_letter: string;
  label: string;
  file_system: string;
  total_gb: number;
  free_gb: number;
}

export interface DiskHardwareEntry {
  model: string;
  serial_number: string;
  capacity_gb: number;
  media_type: string;       // SSD, HDD, NVMe, Unknown
  health_status: string;
  interface_type: string;
  partitions: PartitionEntry[];
}

export interface GpuEntry {
  name: string;
  driver_version: string;
  vram_gb: number;
  status: string;
}

export interface MotherboardInfo {
  manufacturer: string;
  product: string;
  serial_number: string;
  bios_version: string;
  bios_date: string;
}

export interface HardwareInfo {
  cpu: CpuInfo;
  memory: MemoryHardwareInfo;
  disks: DiskHardwareEntry[];
  gpu: GpuEntry[];
  motherboard: MotherboardInfo;
}

// ============================
// OPERATING SYSTEM
// ============================

export interface OSInfo {
  caption: string;            // "Microsoft Windows 11 Enterprise"
  version: string;            // "10.0.22000"
  build_number: string;
  edition: string;
  architecture: string;       // "64-bit"
  product_type: number;       // 1=Workstation, 2=DC, 3=Server
  install_date: string;
  last_boot: string;
  uptime_hours: number;
  activation_status: string;
  domain: string;
  workgroup: string;
  ou_path: string;
  registered_owner: string;
  registered_organization: string;
  pending_reboot: boolean;
  pending_reboot_reasons: string[];
  time_zone: string;
  locale: string;
}

// ============================
// SOFTWARE
// ============================

export interface SoftwareEntry {
  name: string;
  version: string;
  publisher: string;
  install_date: string;
  install_location: string;
  architecture: '32-bit' | '64-bit' | 'unknown';
  is_system_component: boolean;
}

// ============================
// NETWORK
// ============================

export interface IPv4Address {
  address: string;
  subnet_mask: string;
}

export interface NetworkAdapterDetail {
  name: string;
  description: string;
  status: string;
  adapter_type: string;       // Ethernet, Wi-Fi, Virtual
  mac_address: string;
  link_speed_mbps: number;
  ipv4_addresses: IPv4Address[];
  ipv6_addresses: string[];
  default_gateway: string;
  dhcp_enabled: boolean;
  dhcp_server: string;
  dns_servers: string[];
  connection_specific_dns_suffix: string;
}

export interface ProxySettings {
  enabled: boolean;
  server: string;
  bypass_list: string[];
  auto_config_url: string;
}

export interface NetworkConfig {
  adapters: NetworkAdapterDetail[];
  dns_suffix: string;
  dns_search_list: string[];
  wins_servers: string[];
  proxy_settings: ProxySettings;
}

// ============================
// ACTIVE DIRECTORY
// ============================

export interface ADInfo {
  domain_name: string;
  domain_fqdn: string;
  site_name: string;
  computer_ou: string;
  computer_groups: string[];
  last_password_change: string;
  machine_account_name: string;
  domain_controller: string;
}

// ============================
// LOCAL ACCOUNTS
// ============================

export interface LocalAccountInfo {
  name: string;
  full_name: string;
  description: string;
  enabled: boolean;
  is_local_admin: boolean;
  last_logon: string;
  password_last_set: string;
  password_expires: string;
  sid: string;
  source: 'local' | 'domain';
}

// ============================
// SERVICES
// ============================

export interface ServiceInventoryEntry {
  name: string;
  display_name: string;
  status: string;
  start_type: string;
  account: string;
  path_to_executable: string;
  description: string;
  pid: number | null;
  dependencies: string[];
  dependents: string[];
}

// ============================
// PRINTERS & SHARES
// ============================

export interface PrinterEntry {
  name: string;
  driver_name: string;
  port_name: string;
  shared: boolean;
  share_name: string;
  is_default: boolean;
  is_network: boolean;
  status: string;
}

export interface ShareEntry {
  name: string;
  path: string;
  description: string;
  share_type: string;
}

export interface PrintersAndShares {
  printers: PrinterEntry[];
  shares: ShareEntry[];
}

// ============================
// SERVER ROLES & FEATURES
// ============================

export interface RoleFeature {
  name: string;
  display_name: string;
  installed: boolean;
  feature_type: 'Role' | 'RoleService' | 'Feature';
}

// ============================
// ENVIRONMENT SNAPSHOT
// ============================

export interface EnvironmentSnapshot {
  schema_version: number;
  snapshot_id: string;
  collected_at: string;
  collection_duration_ms: number;
  device_id: string;
  tenant_id: string;
  hostname: string;

  hardware: HardwareInfo;
  operating_system: OSInfo;
  installed_software: SoftwareEntry[];
  network: NetworkConfig;
  active_directory: ADInfo | null;
  local_accounts: LocalAccountInfo[];
  services: ServiceInventoryEntry[];
  printers_and_shares: PrintersAndShares;
  server_roles_features: RoleFeature[] | null;
}

// ============================
// CHANGE EVENTS
// ============================

export interface EnvironmentChangeEvent {
  change_id: string;
  timestamp: string;
  section: string;
  field_path: string;
  change_type: 'added' | 'removed' | 'modified';
  previous_value: any;
  new_value: any;
  summary: string;
}

export interface ChangeJournalEntry {
  journal_id: string;
  snapshot_id: string;
  timestamp: string;
  scan_type: 'full' | 'incremental';
  changes: EnvironmentChangeEvent[];
}

// ============================
// PERSISTENCE
// ============================

export interface EnvironmentJournalData {
  entries: ChangeJournalEntry[];
  version: string;
}
