// environment-discovery.ts - Data collection layer for Environment Intelligence
import { Logger } from '../common/logger';
import { Primitives } from '../execution/primitives/index';
import { securePowerShell } from '../execution/primitives/index';
import {
  EnvironmentSnapshot,
  HardwareInfo,
  CpuInfo,
  MemoryHardwareInfo,
  DiskHardwareEntry,
  PartitionEntry,
  GpuEntry,
  MotherboardInfo,
  OSInfo,
  SoftwareEntry,
  NetworkConfig,
  NetworkAdapterDetail,
  IPv4Address,
  ProxySettings,
  ADInfo,
  LocalAccountInfo,
  ServiceInventoryEntry,
  PrintersAndShares,
  PrinterEntry,
  ShareEntry,
  RoleFeature,
} from './environment-intelligence-types';

const INTER_CATEGORY_DELAY_MS = 500;

function tryParseJson(stdout: string): any {
  try {
    const trimmed = stdout.trim();
    if (!trimmed) return null;
    return JSON.parse(trimmed);
  } catch {
    return null;
  }
}

function delay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export class EnvironmentDiscovery {
  private logger: Logger;
  private primitives: Primitives;

  constructor(logger: Logger, primitives: Primitives) {
    this.logger = logger;
    this.primitives = primitives;
  }

  /**
   * Run full environment discovery across all categories.
   * Categories run sequentially with delays to avoid resource spikes.
   */
  async discoverAll(deviceId: string, tenantId: string): Promise<EnvironmentSnapshot> {
    const startTime = Date.now();
    const snapshotId = this.generateId();

    const hardware = await this.discoverHardware();
    await delay(INTER_CATEGORY_DELAY_MS);

    const operatingSystem = await this.discoverOperatingSystem();
    await delay(INTER_CATEGORY_DELAY_MS);

    const installedSoftware = await this.discoverFullSoftware();
    await delay(INTER_CATEGORY_DELAY_MS);

    const network = await this.discoverNetworkConfig();
    await delay(INTER_CATEGORY_DELAY_MS);

    const activeDirectory = await this.discoverActiveDirectory();
    await delay(INTER_CATEGORY_DELAY_MS);

    const localAccounts = await this.discoverLocalAccounts();
    await delay(INTER_CATEGORY_DELAY_MS);

    const services = await this.discoverAllServices();
    await delay(INTER_CATEGORY_DELAY_MS);

    const printersAndShares = await this.discoverPrintersAndShares();
    await delay(INTER_CATEGORY_DELAY_MS);

    const serverRolesFeatures = await this.discoverServerRoles(operatingSystem.product_type);

    const hostname = require('os').hostname();

    return {
      schema_version: 1,
      snapshot_id: snapshotId,
      collected_at: new Date().toISOString(),
      collection_duration_ms: Date.now() - startTime,
      device_id: deviceId,
      tenant_id: tenantId,
      hostname,
      hardware,
      operating_system: operatingSystem,
      installed_software: installedSoftware,
      network,
      active_directory: activeDirectory,
      local_accounts: localAccounts,
      services,
      printers_and_shares: printersAndShares,
      server_roles_features: serverRolesFeatures,
    };
  }

  /**
   * Run discovery for a single section only (for incremental checks).
   */
  async discoverSection(section: string): Promise<any> {
    switch (section) {
      case 'services': return this.discoverAllServices();
      case 'network': return this.discoverNetworkConfig();
      case 'installed_software': return this.discoverFullSoftware();
      case 'local_accounts': return this.discoverLocalAccounts();
      default:
        this.logger.warn('Unknown discovery section requested', { section });
        return null;
    }
  }

  // ============================
  // HARDWARE DISCOVERY
  // ============================

  async discoverHardware(): Promise<HardwareInfo> {
    const [cpu, memory, disks, gpu, motherboard] = await Promise.all([
      this.discoverCpu(),
      this.discoverMemoryHardware(),
      this.discoverDiskHardware(),
      this.discoverGpu(),
      this.discoverMotherboardBIOS(),
    ]);

    return { cpu, memory, disks, gpu, motherboard };
  }

  private async discoverCpu(): Promise<CpuInfo> {
    try {
      const result = await this.primitives.getProcessorDetails();
      if (result.success && result.data) {
        return {
          model: result.data.name,
          cores: result.data.cores,
          logical_processors: result.data.logical_processors,
          max_clock_mhz: result.data.max_clock_mhz,
          architecture: require('os').arch() === 'x64' ? 'x64' : 'x86',
        };
      }
    } catch (err) {
      this.logger.warn('CPU discovery failed', err);
    }
    return { model: 'Unknown', cores: 0, logical_processors: 0, max_clock_mhz: 0, architecture: 'Unknown' };
  }

  private discoverMemoryHardware(): MemoryHardwareInfo {
    try {
      const script = `
        $mem = Get-CimInstance Win32_PhysicalMemory | Select-Object Capacity, Speed, SMBIOSMemoryType
        $slots = (Get-CimInstance Win32_PhysicalMemoryArray).MemoryDevices
        $totalBytes = ($mem | Measure-Object -Property Capacity -Sum).Sum
        $typeMap = @{ 20='DDR'; 21='DDR2'; 22='DDR2'; 24='DDR3'; 26='DDR4'; 34='DDR5' }
        $memType = if ($mem.Count -gt 0) { $typeMap[[int]$mem[0].SMBIOSMemoryType] } else { $null }
        $speed = if ($mem.Count -gt 0) { $mem[0].Speed } else { 0 }
        @{
          total_gb = [math]::Round($totalBytes / 1GB, 2)
          type = if ($memType) { $memType } else { 'Unknown' }
          speed_mhz = $speed
          slots_used = $mem.Count
          slots_total = if ($slots) { $slots } else { $mem.Count }
        } | ConvertTo-Json
      `;
      const result = securePowerShell(script, { timeout: 15000 });
      if (result.success) {
        const data = tryParseJson(result.stdout);
        if (data) {
          return {
            total_gb: data.total_gb || 0,
            type: data.type || 'Unknown',
            speed_mhz: data.speed_mhz || 0,
            slots_used: data.slots_used || 0,
            slots_total: data.slots_total || 0,
          };
        }
      }
    } catch (err) {
      this.logger.warn('Memory hardware discovery failed', err);
    }
    const totalMem = require('os').totalmem();
    return {
      total_gb: Math.round(totalMem / (1024 * 1024 * 1024) * 100) / 100,
      type: 'Unknown',
      speed_mhz: 0,
      slots_used: 0,
      slots_total: 0,
    };
  }

  private async discoverDiskHardware(): Promise<DiskHardwareEntry[]> {
    try {
      const script = `
        $disks = Get-CimInstance Win32_DiskDrive | Select-Object Model, SerialNumber, Size, InterfaceType, MediaType, Index
        $physDisks = @{}
        try {
          Get-CimInstance -Namespace root/Microsoft/Windows/Storage -ClassName MSFT_PhysicalDisk -ErrorAction SilentlyContinue | ForEach-Object {
            $physDisks[$_.DeviceId] = @{ MediaType = $_.MediaType; HealthStatus = $_.HealthStatus }
          }
        } catch {}
        $partitions = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceID, VolumeName, FileSystem, Size, FreeSpace

        $results = @()
        foreach ($d in $disks) {
          $pd = $physDisks["$($d.Index)"]
          $mediaTypeStr = switch ([int]$pd.MediaType) { 3 { 'HDD' }; 4 { 'SSD' }; 5 { 'SCM' }; default { if ($d.MediaType -match 'SSD|Solid') { 'SSD' } elseif ($d.MediaType -match 'Fixed') { 'HDD' } else { 'Unknown' } } }
          $healthStr = switch ([int]$pd.HealthStatus) { 0 { 'Healthy' }; 1 { 'Warning' }; 2 { 'Unhealthy' }; default { 'Unknown' } }
          $results += @{
            model = $d.Model
            serial_number = ($d.SerialNumber -replace '\\s+','').Trim()
            capacity_gb = [math]::Round($d.Size / 1GB, 2)
            media_type = $mediaTypeStr
            health_status = $healthStr
            interface_type = $d.InterfaceType
          }
        }

        $partList = @()
        foreach ($p in $partitions) {
          $partList += @{
            drive_letter = $p.DeviceID
            label = if ($p.VolumeName) { $p.VolumeName } else { '' }
            file_system = if ($p.FileSystem) { $p.FileSystem } else { '' }
            total_gb = [math]::Round($p.Size / 1GB, 2)
            free_gb = [math]::Round($p.FreeSpace / 1GB, 2)
          }
        }

        @{ disks = $results; partitions = $partList } | ConvertTo-Json -Depth 5
      `;
      const result = securePowerShell(script, { timeout: 30000 });
      if (result.success) {
        const data = tryParseJson(result.stdout);
        if (data) {
          const disks: DiskHardwareEntry[] = (Array.isArray(data.disks) ? data.disks : [data.disks]).filter(Boolean).map((d: any) => ({
            model: d.model || 'Unknown',
            serial_number: d.serial_number || '',
            capacity_gb: d.capacity_gb || 0,
            media_type: d.media_type || 'Unknown',
            health_status: d.health_status || 'Unknown',
            interface_type: d.interface_type || 'Unknown',
            partitions: [] as PartitionEntry[],
          }));

          const partitions: PartitionEntry[] = (Array.isArray(data.partitions) ? data.partitions : [data.partitions]).filter(Boolean).map((p: any) => ({
            drive_letter: p.drive_letter || '',
            label: p.label || '',
            file_system: p.file_system || '',
            total_gb: p.total_gb || 0,
            free_gb: p.free_gb || 0,
          }));

          // Attach partitions to the first disk (simple heuristic for single-disk systems)
          // For multi-disk, exact mapping would require Win32_DiskDriveToDiskPartition
          if (disks.length > 0) {
            disks[0].partitions = partitions;
          }

          return disks;
        }
      }
    } catch (err) {
      this.logger.warn('Disk hardware discovery failed', err);
    }
    return [];
  }

  private discoverGpu(): GpuEntry[] {
    try {
      const script = `
        Get-CimInstance Win32_VideoController | ForEach-Object {
          @{
            name = $_.Name
            driver_version = $_.DriverVersion
            vram_gb = [math]::Round($_.AdapterRAM / 1GB, 2)
            status = $_.Status
          }
        } | ConvertTo-Json
      `;
      const result = securePowerShell(script, { timeout: 10000 });
      if (result.success) {
        const data = tryParseJson(result.stdout);
        if (data) {
          const items = Array.isArray(data) ? data : [data];
          return items.map((g: any) => ({
            name: g.name || 'Unknown',
            driver_version: g.driver_version || '',
            vram_gb: g.vram_gb || 0,
            status: g.status || 'Unknown',
          }));
        }
      }
    } catch (err) {
      this.logger.warn('GPU discovery failed', err);
    }
    return [];
  }

  private discoverMotherboardBIOS(): MotherboardInfo {
    try {
      const script = `
        $board = Get-CimInstance Win32_BaseBoard | Select-Object Manufacturer, Product, SerialNumber
        $bios = Get-CimInstance Win32_BIOS | Select-Object SMBIOSBIOSVersion, ReleaseDate
        @{
          manufacturer = $board.Manufacturer
          product = $board.Product
          serial_number = $board.SerialNumber
          bios_version = $bios.SMBIOSBIOSVersion
          bios_date = if ($bios.ReleaseDate) { $bios.ReleaseDate.ToString('yyyy-MM-dd') } else { '' }
        } | ConvertTo-Json
      `;
      const result = securePowerShell(script, { timeout: 10000 });
      if (result.success) {
        const data = tryParseJson(result.stdout);
        if (data) {
          return {
            manufacturer: data.manufacturer || 'Unknown',
            product: data.product || 'Unknown',
            serial_number: data.serial_number || '',
            bios_version: data.bios_version || '',
            bios_date: data.bios_date || '',
          };
        }
      }
    } catch (err) {
      this.logger.warn('Motherboard/BIOS discovery failed', err);
    }
    return { manufacturer: 'Unknown', product: 'Unknown', serial_number: '', bios_version: '', bios_date: '' };
  }

  // ============================
  // OS DISCOVERY
  // ============================

  async discoverOperatingSystem(): Promise<OSInfo> {
    try {
      const script = `
        $os = Get-CimInstance Win32_OperatingSystem
        $cs = Get-CimInstance Win32_ComputerSystem
        $tz = Get-CimInstance Win32_TimeZone

        # Activation status
        $activation = 'Unknown'
        try {
          $slmgr = Get-CimInstance SoftwareLicensingProduct -Filter "ApplicationId='55c92734-d682-4d71-983e-d6ec3f16059f' AND LicenseStatus=1" -ErrorAction SilentlyContinue
          if ($slmgr) { $activation = 'Activated' } else { $activation = 'Not Activated' }
        } catch {}

        # Pending reboot check
        $pendingReasons = @()
        if (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending') { $pendingReasons += 'CBS' }
        if (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired') { $pendingReasons += 'WindowsUpdate' }
        try {
          $pfe = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\\CurrentControlSet\\Control\\Session Manager')
          $pfv = $pfe.GetValue('PendingFileRenameOperations')
          if ($pfv) { $pendingReasons += 'PendingFileRename' }
        } catch {}

        # OU path
        $ouPath = ''
        try {
          $searcher = New-Object System.DirectoryServices.DirectorySearcher
          $searcher.Filter = "(&(objectCategory=computer)(cn=$env:COMPUTERNAME))"
          $found = $searcher.FindOne()
          if ($found) {
            $dn = $found.Properties['distinguishedname'][0]
            $ouPath = ($dn -split ',', 2)[1]
          }
        } catch {}

        @{
          caption = $os.Caption
          version = $os.Version
          build_number = $os.BuildNumber
          edition = $os.Caption -replace 'Microsoft Windows \\d+ ',''
          architecture = $os.OSArchitecture
          product_type = $os.ProductType
          install_date = $os.InstallDate.ToString('o')
          last_boot = $os.LastBootUpTime.ToString('o')
          uptime_hours = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 1)
          activation_status = $activation
          domain = if ($cs.PartOfDomain) { $cs.Domain } else { '' }
          workgroup = if (-not $cs.PartOfDomain) { $cs.Workgroup } else { '' }
          ou_path = $ouPath
          registered_owner = $os.RegisteredUser
          registered_organization = $os.Organization
          pending_reboot = ($pendingReasons.Count -gt 0)
          pending_reboot_reasons = $pendingReasons
          time_zone = $tz.Caption
          locale = (Get-Culture).Name
        } | ConvertTo-Json -Depth 3
      `;
      const result = securePowerShell(script, { timeout: 20000 });
      if (result.success) {
        const data = tryParseJson(result.stdout);
        if (data) {
          return {
            caption: data.caption || '',
            version: data.version || '',
            build_number: data.build_number || '',
            edition: data.edition || '',
            architecture: data.architecture || '',
            product_type: data.product_type || 1,
            install_date: data.install_date || '',
            last_boot: data.last_boot || '',
            uptime_hours: data.uptime_hours || 0,
            activation_status: data.activation_status || 'Unknown',
            domain: data.domain || '',
            workgroup: data.workgroup || '',
            ou_path: data.ou_path || '',
            registered_owner: data.registered_owner || '',
            registered_organization: data.registered_organization || '',
            pending_reboot: data.pending_reboot || false,
            pending_reboot_reasons: Array.isArray(data.pending_reboot_reasons) ? data.pending_reboot_reasons : [],
            time_zone: data.time_zone || '',
            locale: data.locale || '',
          };
        }
      }
    } catch (err) {
      this.logger.warn('OS discovery failed', err);
    }
    return {
      caption: '', version: '', build_number: '', edition: '', architecture: '',
      product_type: 1, install_date: '', last_boot: '', uptime_hours: 0,
      activation_status: 'Unknown', domain: '', workgroup: '', ou_path: '',
      registered_owner: '', registered_organization: '',
      pending_reboot: false, pending_reboot_reasons: [], time_zone: '', locale: '',
    };
  }

  // ============================
  // SOFTWARE DISCOVERY
  // ============================

  async discoverFullSoftware(): Promise<SoftwareEntry[]> {
    try {
      const script = `
        $paths = @(
          'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
          'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'
        )
        $software = @()
        foreach ($regPath in $paths) {
          $is32 = $regPath -match 'WOW6432Node'
          Get-ItemProperty $regPath -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | ForEach-Object {
            $software += @{
              name = $_.DisplayName
              version = if ($_.DisplayVersion) { $_.DisplayVersion } else { '' }
              publisher = if ($_.Publisher) { $_.Publisher } else { '' }
              install_date = if ($_.InstallDate) { $_.InstallDate } else { '' }
              install_location = if ($_.InstallLocation) { $_.InstallLocation } else { '' }
              architecture = if ($is32) { '32-bit' } else { '64-bit' }
              is_system_component = if ($_.SystemComponent -eq 1) { $true } else { $false }
            }
          }
        }
        $software | ConvertTo-Json -Depth 3 -Compress
      `;
      const result = securePowerShell(script, { timeout: 30000 });
      if (result.success) {
        const data = tryParseJson(result.stdout);
        if (data) {
          const items = Array.isArray(data) ? data : [data];
          return items.filter((s: any) => s && s.name).map((s: any) => ({
            name: s.name,
            version: s.version || '',
            publisher: s.publisher || '',
            install_date: s.install_date || '',
            install_location: s.install_location || '',
            architecture: s.architecture === '32-bit' ? '32-bit' as const : s.architecture === '64-bit' ? '64-bit' as const : 'unknown' as const,
            is_system_component: s.is_system_component || false,
          }));
        }
      }
    } catch (err) {
      this.logger.warn('Software discovery failed', err);
    }
    return [];
  }

  // ============================
  // NETWORK DISCOVERY
  // ============================

  async discoverNetworkConfig(): Promise<NetworkConfig> {
    const adapters = await this.discoverNetworkAdapters();
    const extended = this.discoverNetworkExtended();

    return {
      adapters,
      dns_suffix: extended.dns_suffix,
      dns_search_list: extended.dns_search_list,
      wins_servers: extended.wins_servers,
      proxy_settings: extended.proxy_settings,
    };
  }

  private async discoverNetworkAdapters(): Promise<NetworkAdapterDetail[]> {
    try {
      const script = `
        $adapters = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
        $physAdapters = Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.NetConnectionStatus -ne $null }

        $results = @()
        foreach ($a in $adapters) {
          $phys = $physAdapters | Where-Object { $_.Index -eq $a.Index }
          $adapterType = if ($phys.AdapterType) { $phys.AdapterType } else { 'Unknown' }
          if ($a.Description -match 'Virtual|VPN|Hyper-V|VMware|VirtualBox') { $adapterType = 'Virtual' }
          elseif ($a.Description -match 'Wi-Fi|Wireless|WiFi|802\.11') { $adapterType = 'Wi-Fi' }
          elseif ($adapterType -match 'Ethernet') { $adapterType = 'Ethernet' }

          $ipv4 = @()
          $ipv6 = @()
          if ($a.IPAddress) {
            for ($i = 0; $i -lt $a.IPAddress.Count; $i++) {
              $ip = $a.IPAddress[$i]
              if ($ip -match ':') {
                $ipv6 += $ip
              } else {
                $mask = if ($a.IPSubnet -and $i -lt $a.IPSubnet.Count) { $a.IPSubnet[$i] } else { '' }
                $ipv4 += @{ address = $ip; subnet_mask = $mask }
              }
            }
          }

          $results += @{
            name = if ($phys.NetConnectionID) { $phys.NetConnectionID } else { $a.Description }
            description = $a.Description
            status = if ($phys.NetConnectionStatus -eq 2) { 'Up' } else { 'Down' }
            adapter_type = $adapterType
            mac_address = if ($a.MACAddress) { $a.MACAddress } else { '' }
            link_speed_mbps = if ($phys.Speed) { [math]::Round($phys.Speed / 1000000, 0) } else { 0 }
            ipv4_addresses = $ipv4
            ipv6_addresses = $ipv6
            default_gateway = if ($a.DefaultIPGateway) { $a.DefaultIPGateway[0] } else { '' }
            dhcp_enabled = $a.DHCPEnabled
            dhcp_server = if ($a.DHCPServer) { $a.DHCPServer } else { '' }
            dns_servers = if ($a.DNSServerSearchOrder) { @($a.DNSServerSearchOrder) } else { @() }
            connection_specific_dns_suffix = if ($a.DNSDomainSuffixSearchOrder) { $a.DNSDomainSuffixSearchOrder[0] } else { '' }
          }
        }
        $results | ConvertTo-Json -Depth 5 -Compress
      `;
      const result = securePowerShell(script, { timeout: 15000 });
      if (result.success) {
        const data = tryParseJson(result.stdout);
        if (data) {
          const items = Array.isArray(data) ? data : [data];
          return items.filter(Boolean).map((a: any) => ({
            name: a.name || '',
            description: a.description || '',
            status: a.status || 'Unknown',
            adapter_type: a.adapter_type || 'Unknown',
            mac_address: a.mac_address || '',
            link_speed_mbps: a.link_speed_mbps || 0,
            ipv4_addresses: Array.isArray(a.ipv4_addresses) ? a.ipv4_addresses.map((ip: any) => ({
              address: ip.address || '',
              subnet_mask: ip.subnet_mask || '',
            })) : [],
            ipv6_addresses: Array.isArray(a.ipv6_addresses) ? a.ipv6_addresses : [],
            default_gateway: a.default_gateway || '',
            dhcp_enabled: a.dhcp_enabled || false,
            dhcp_server: a.dhcp_server || '',
            dns_servers: Array.isArray(a.dns_servers) ? a.dns_servers : [],
            connection_specific_dns_suffix: a.connection_specific_dns_suffix || '',
          }));
        }
      }
    } catch (err) {
      this.logger.warn('Network adapter discovery failed', err);
    }
    return [];
  }

  private discoverNetworkExtended(): { dns_suffix: string; dns_search_list: string[]; wins_servers: string[]; proxy_settings: ProxySettings } {
    const defaults = {
      dns_suffix: '',
      dns_search_list: [] as string[],
      wins_servers: [] as string[],
      proxy_settings: { enabled: false, server: '', bypass_list: [] as string[], auto_config_url: '' },
    };

    try {
      const script = `
        $dnsSuffix = (Get-DnsClientGlobalSetting -ErrorAction SilentlyContinue).SuffixSearchList
        $primarySuffix = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters' -ErrorAction SilentlyContinue).Domain

        # Proxy settings
        $proxy = Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -ErrorAction SilentlyContinue
        $proxyEnabled = if ($proxy.ProxyEnable) { [bool]$proxy.ProxyEnable } else { $false }
        $proxyServer = if ($proxy.ProxyServer) { $proxy.ProxyServer } else { '' }
        $proxyBypass = if ($proxy.ProxyOverride) { $proxy.ProxyOverride -split ';' } else { @() }
        $autoConfig = if ($proxy.AutoConfigURL) { $proxy.AutoConfigURL } else { '' }

        # WINS
        $wins = @()
        try {
          Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "WINSPrimaryServer IS NOT NULL" -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.WINSPrimaryServer -and $wins -notcontains $_.WINSPrimaryServer) { $wins += $_.WINSPrimaryServer }
            if ($_.WINSSecondaryServer -and $wins -notcontains $_.WINSSecondaryServer) { $wins += $_.WINSSecondaryServer }
          }
        } catch {}

        @{
          dns_suffix = if ($primarySuffix) { $primarySuffix } else { '' }
          dns_search_list = if ($dnsSuffix) { @($dnsSuffix) } else { @() }
          wins_servers = $wins
          proxy_settings = @{
            enabled = $proxyEnabled
            server = $proxyServer
            bypass_list = $proxyBypass
            auto_config_url = $autoConfig
          }
        } | ConvertTo-Json -Depth 3
      `;
      const result = securePowerShell(script, { timeout: 10000 });
      if (result.success) {
        const data = tryParseJson(result.stdout);
        if (data) {
          return {
            dns_suffix: data.dns_suffix || '',
            dns_search_list: Array.isArray(data.dns_search_list) ? data.dns_search_list : [],
            wins_servers: Array.isArray(data.wins_servers) ? data.wins_servers : [],
            proxy_settings: {
              enabled: data.proxy_settings?.enabled || false,
              server: data.proxy_settings?.server || '',
              bypass_list: Array.isArray(data.proxy_settings?.bypass_list) ? data.proxy_settings.bypass_list : [],
              auto_config_url: data.proxy_settings?.auto_config_url || '',
            },
          };
        }
      }
    } catch (err) {
      this.logger.warn('Extended network discovery failed', err);
    }
    return defaults;
  }

  // ============================
  // ACTIVE DIRECTORY DISCOVERY
  // ============================

  async discoverActiveDirectory(): Promise<ADInfo | null> {
    try {
      const script = `
        $cs = Get-CimInstance Win32_ComputerSystem
        if (-not $cs.PartOfDomain) {
          Write-Output 'null'
          return
        }

        $domainName = $cs.Domain
        $siteName = ''
        $dc = ''
        $ou = ''
        $groups = @()
        $lastPwdChange = ''
        $machineAccount = "$env:COMPUTERNAME$"

        # Get site and DC via nltest
        try {
          $nltest = & nltest /dsgetdc:$domainName 2>$null
          if ($nltest) {
            $dcLine = $nltest | Where-Object { $_ -match 'DC: \\\\(.+)' }
            if ($dcLine -and $Matches[1]) { $dc = $Matches[1] }
            $siteLine = $nltest | Where-Object { $_ -match 'Our Site Name: (.+)' }
            if ($siteLine -and $Matches[1]) { $siteName = $Matches[1] }
          }
        } catch {}

        # Get OU and groups via ADSI
        try {
          $searcher = New-Object System.DirectoryServices.DirectorySearcher
          $searcher.Filter = "(&(objectCategory=computer)(cn=$env:COMPUTERNAME))"
          $searcher.PropertiesToLoad.AddRange(@('distinguishedname','memberof','pwdlastset'))
          $found = $searcher.FindOne()
          if ($found) {
            $dn = $found.Properties['distinguishedname'][0]
            $ou = ($dn -split ',', 2)[1]
            $found.Properties['memberof'] | ForEach-Object {
              $groups += ($_ -split ',')[0] -replace '^CN=',''
            }
            $pwdLastSet = $found.Properties['pwdlastset'][0]
            if ($pwdLastSet) {
              $lastPwdChange = [DateTime]::FromFileTimeUtc($pwdLastSet).ToString('o')
            }
          }
        } catch {}

        @{
          domain_name = ($domainName -split '\\.',2)[0]
          domain_fqdn = $domainName
          site_name = $siteName
          computer_ou = $ou
          computer_groups = $groups
          last_password_change = $lastPwdChange
          machine_account_name = $machineAccount
          domain_controller = $dc
        } | ConvertTo-Json -Depth 3
      `;
      const result = securePowerShell(script, { timeout: 15000 });
      if (result.success) {
        const trimmed = result.stdout.trim();
        if (trimmed === 'null' || !trimmed) return null;

        const data = tryParseJson(trimmed);
        if (data) {
          return {
            domain_name: data.domain_name || '',
            domain_fqdn: data.domain_fqdn || '',
            site_name: data.site_name || '',
            computer_ou: data.computer_ou || '',
            computer_groups: Array.isArray(data.computer_groups) ? data.computer_groups : [],
            last_password_change: data.last_password_change || '',
            machine_account_name: data.machine_account_name || '',
            domain_controller: data.domain_controller || '',
          };
        }
      }
    } catch (err) {
      this.logger.warn('Active Directory discovery failed (may not be domain-joined)', err);
    }
    return null;
  }

  // ============================
  // LOCAL ACCOUNTS DISCOVERY
  // ============================

  async discoverLocalAccounts(): Promise<LocalAccountInfo[]> {
    try {
      const script = `
        $admins = @()
        try {
          Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | ForEach-Object {
            $admins += $_.SID.Value
          }
        } catch {}

        $users = Get-LocalUser -ErrorAction SilentlyContinue | ForEach-Object {
          @{
            name = $_.Name
            full_name = if ($_.FullName) { $_.FullName } else { '' }
            description = if ($_.Description) { $_.Description } else { '' }
            enabled = $_.Enabled
            is_local_admin = $admins -contains $_.SID.Value
            last_logon = if ($_.LastLogon) { $_.LastLogon.ToString('o') } else { '' }
            password_last_set = if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString('o') } else { '' }
            password_expires = if ($_.PasswordExpires) { $_.PasswordExpires.ToString('o') } else { 'Never' }
            sid = $_.SID.Value
            source = if ($_.PrincipalSource -eq 'Local') { 'local' } else { 'domain' }
          }
        }
        $users | ConvertTo-Json -Depth 3 -Compress
      `;
      const result = securePowerShell(script, { timeout: 10000 });
      if (result.success) {
        const data = tryParseJson(result.stdout);
        if (data) {
          const items = Array.isArray(data) ? data : [data];
          return items.filter(Boolean).map((u: any) => ({
            name: u.name || '',
            full_name: u.full_name || '',
            description: u.description || '',
            enabled: u.enabled || false,
            is_local_admin: u.is_local_admin || false,
            last_logon: u.last_logon || '',
            password_last_set: u.password_last_set || '',
            password_expires: u.password_expires || '',
            sid: u.sid || '',
            source: u.source === 'domain' ? 'domain' as const : 'local' as const,
          }));
        }
      }
    } catch (err) {
      this.logger.warn('Local accounts discovery failed', err);
    }
    return [];
  }

  // ============================
  // SERVICES DISCOVERY
  // ============================

  async discoverAllServices(): Promise<ServiceInventoryEntry[]> {
    try {
      const script = `
        Get-CimInstance Win32_Service | ForEach-Object {
          $deps = @()
          $dependents = @()
          try {
            $svc = Get-Service -Name $_.Name -ErrorAction SilentlyContinue
            if ($svc) {
              $deps = @($svc.ServicesDependedOn | ForEach-Object { $_.Name })
              $dependents = @($svc.DependentServices | ForEach-Object { $_.Name })
            }
          } catch {}
          @{
            name = $_.Name
            display_name = $_.DisplayName
            status = $_.State
            start_type = $_.StartMode
            account = if ($_.StartName) { $_.StartName } else { '' }
            path_to_executable = if ($_.PathName) { $_.PathName } else { '' }
            description = if ($_.Description) { $_.Description } else { '' }
            pid = if ($_.ProcessId -and $_.State -eq 'Running') { $_.ProcessId } else { $null }
            dependencies = $deps
            dependents = $dependents
          }
        } | ConvertTo-Json -Depth 3 -Compress
      `;
      const result = securePowerShell(script, { timeout: 30000 });
      if (result.success) {
        const data = tryParseJson(result.stdout);
        if (data) {
          const items = Array.isArray(data) ? data : [data];
          return items.filter(Boolean).map((s: any) => ({
            name: s.name || '',
            display_name: s.display_name || '',
            status: s.status || '',
            start_type: s.start_type || '',
            account: s.account || '',
            path_to_executable: s.path_to_executable || '',
            description: s.description || '',
            pid: s.pid || null,
            dependencies: Array.isArray(s.dependencies) ? s.dependencies : [],
            dependents: Array.isArray(s.dependents) ? s.dependents : [],
          }));
        }
      }
    } catch (err) {
      this.logger.warn('Services discovery failed', err);
    }
    return [];
  }

  // ============================
  // PRINTERS & SHARES DISCOVERY
  // ============================

  async discoverPrintersAndShares(): Promise<PrintersAndShares> {
    const printers = this.discoverPrinters();
    const shares = this.discoverShares();
    return { printers, shares };
  }

  private discoverPrinters(): PrinterEntry[] {
    try {
      const script = `
        Get-Printer -ErrorAction SilentlyContinue | ForEach-Object {
          @{
            name = $_.Name
            driver_name = if ($_.DriverName) { $_.DriverName } else { '' }
            port_name = if ($_.PortName) { $_.PortName } else { '' }
            shared = $_.Shared
            share_name = if ($_.ShareName) { $_.ShareName } else { '' }
            is_default = $false
            is_network = ($_.Type -eq 'Connection')
            status = $_.PrinterStatus.ToString()
          }
        } | ConvertTo-Json -Depth 3 -Compress
      `;
      const result = securePowerShell(script, { timeout: 10000 });
      if (result.success) {
        const data = tryParseJson(result.stdout);
        if (data) {
          const items = Array.isArray(data) ? data : [data];
          return items.filter(Boolean).map((p: any) => ({
            name: p.name || '',
            driver_name: p.driver_name || '',
            port_name: p.port_name || '',
            shared: p.shared || false,
            share_name: p.share_name || '',
            is_default: p.is_default || false,
            is_network: p.is_network || false,
            status: p.status || '',
          }));
        }
      }
    } catch (err) {
      this.logger.warn('Printer discovery failed', err);
    }
    return [];
  }

  private discoverShares(): ShareEntry[] {
    try {
      const script = `
        Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '^(IPC|ADMIN|[A-Z])\\$' } | ForEach-Object {
          @{
            name = $_.Name
            path = if ($_.Path) { $_.Path } else { '' }
            description = if ($_.Description) { $_.Description } else { '' }
            share_type = $_.ShareType.ToString()
          }
        } | ConvertTo-Json -Depth 3 -Compress
      `;
      const result = securePowerShell(script, { timeout: 10000 });
      if (result.success) {
        const data = tryParseJson(result.stdout);
        if (data) {
          const items = Array.isArray(data) ? data : [data];
          return items.filter(Boolean).map((s: any) => ({
            name: s.name || '',
            path: s.path || '',
            description: s.description || '',
            share_type: s.share_type || '',
          }));
        }
      }
    } catch (err) {
      this.logger.warn('Shares discovery failed', err);
    }
    return [];
  }

  // ============================
  // SERVER ROLES & FEATURES
  // ============================

  async discoverServerRoles(productType: number): Promise<RoleFeature[] | null> {
    // ProductType: 1=Workstation, 2=Domain Controller, 3=Server
    if (productType === 1) return null;

    try {
      const script = `
        try {
          Import-Module ServerManager -ErrorAction SilentlyContinue
          Get-WindowsFeature | Where-Object { $_.Installed } | ForEach-Object {
            @{
              name = $_.Name
              display_name = $_.DisplayName
              installed = $true
              feature_type = switch ($_.FeatureType) { 'Role' { 'Role' }; 'Role Service' { 'RoleService' }; default { 'Feature' } }
            }
          } | ConvertTo-Json -Depth 3 -Compress
        } catch {
          Write-Output 'null'
        }
      `;
      const result = securePowerShell(script, { timeout: 30000 });
      if (result.success) {
        const trimmed = result.stdout.trim();
        if (trimmed === 'null' || !trimmed) return null;

        const data = tryParseJson(trimmed);
        if (data) {
          const items = Array.isArray(data) ? data : [data];
          return items.filter(Boolean).map((r: any) => ({
            name: r.name || '',
            display_name: r.display_name || '',
            installed: r.installed || false,
            feature_type: r.feature_type || 'Feature',
          }));
        }
      }
    } catch (err) {
      this.logger.warn('Server roles discovery failed (may not be Server OS)', err);
    }
    return null;
  }

  // ============================
  // UTILITY
  // ============================

  private generateId(): string {
    const crypto = require('crypto');
    return crypto.randomBytes(16).toString('hex');
  }
}
