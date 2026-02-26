// environment-intelligence.ts - Environment Intelligence service
// Manages environment discovery, change detection, and living documentation
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { Logger } from '../common/logger';
import { Primitives } from '../execution/primitives/index';
import { EnvironmentDiscovery } from './environment-discovery';
import {
  EnvironmentSnapshot,
  EnvironmentChangeEvent,
  ChangeJournalEntry,
  EnvironmentJournalData,
} from './environment-intelligence-types';

const FULL_SCAN_INTERVAL_MS = 4 * 60 * 60 * 1000;  // 4 hours
const MIN_SCAN_GAP_MS = 2 * 60 * 60 * 1000;         // 2 hours — skip if last scan too recent
const STARTUP_DELAY_MS = 20000;                       // 20s after start
const JOURNAL_MAX_AGE_DAYS = 90;
const JOURNAL_MAX_ENTRIES = 1000;

export type EnvironmentChangeCallback = (changes: EnvironmentChangeEvent[]) => void;

export class EnvironmentIntelligence {
  private logger: Logger;
  private dataDir: string;
  private discovery: EnvironmentDiscovery;
  private currentSnapshot: EnvironmentSnapshot | null = null;
  private snapshotPath: string;
  private journalPath: string;
  private fullScanTimer: NodeJS.Timeout | null = null;
  private startupTimer: NodeJS.Timeout | null = null;
  private onChangesDetected: EnvironmentChangeCallback | null = null;
  private isScanning = false;
  private deviceId = '';
  private tenantId = '';

  constructor(logger: Logger, dataDir: string) {
    this.logger = logger;
    this.dataDir = dataDir;
    this.snapshotPath = path.join(dataDir, 'environment-snapshot.json');
    this.journalPath = path.join(dataDir, 'environment-journal.json');

    const primitives = new Primitives(logger, dataDir);
    this.discovery = new EnvironmentDiscovery(logger, primitives);
  }

  setChangeCallback(cb: EnvironmentChangeCallback): void {
    this.onChangesDetected = cb;
  }

  setDeviceInfo(deviceId: string, tenantId: string): void {
    this.deviceId = deviceId;
    this.tenantId = tenantId;
  }

  async start(): Promise<void> {
    this.logger.info('Environment Intelligence starting');

    // Load previous snapshot from disk
    this.currentSnapshot = this.loadSnapshot();

    // Determine if we should scan now or wait
    const lastScanTime = this.currentSnapshot ? new Date(this.currentSnapshot.collected_at).getTime() : 0;
    const timeSinceLastScan = Date.now() - lastScanTime;

    if (timeSinceLastScan < MIN_SCAN_GAP_MS && this.currentSnapshot) {
      this.logger.info('Recent environment snapshot exists, deferring full scan', {
        last_scan: this.currentSnapshot.collected_at,
        hours_ago: Math.round(timeSinceLastScan / 3600000 * 10) / 10,
      });
    } else {
      // Schedule initial scan with startup delay
      this.startupTimer = setTimeout(() => {
        this.runFullScan().catch(err =>
          this.logger.error('Initial environment scan failed', err)
        );
      }, STARTUP_DELAY_MS);
    }

    // Schedule recurring full scans
    this.fullScanTimer = setInterval(() => {
      this.runFullScan().catch(err =>
        this.logger.error('Scheduled environment scan failed', err)
      );
    }, FULL_SCAN_INTERVAL_MS);

    this.logger.info('Environment Intelligence started', {
      has_snapshot: !!this.currentSnapshot,
      scan_interval_hours: FULL_SCAN_INTERVAL_MS / 3600000,
    });
  }

  stop(): void {
    if (this.fullScanTimer) {
      clearInterval(this.fullScanTimer);
      this.fullScanTimer = null;
    }
    if (this.startupTimer) {
      clearTimeout(this.startupTimer);
      this.startupTimer = null;
    }
    this.logger.info('Environment Intelligence stopped');
  }

  // ============================
  // SCANNING
  // ============================

  async runFullScan(): Promise<EnvironmentSnapshot> {
    if (this.isScanning) {
      this.logger.warn('Environment scan already in progress, skipping');
      return this.currentSnapshot!;
    }

    this.isScanning = true;
    this.logger.info('Starting full environment discovery scan');

    try {
      const previousSnapshot = this.currentSnapshot;
      const newSnapshot = await this.discovery.discoverAll(this.deviceId, this.tenantId);

      // Detect changes
      if (previousSnapshot) {
        const changes = this.diffSnapshots(previousSnapshot, newSnapshot);
        if (changes.length > 0) {
          this.logger.info('Environment changes detected', { count: changes.length });

          const journalEntry: ChangeJournalEntry = {
            journal_id: crypto.randomBytes(8).toString('hex'),
            snapshot_id: newSnapshot.snapshot_id,
            timestamp: new Date().toISOString(),
            scan_type: 'full',
            changes,
          };
          this.appendToJournal(journalEntry);

          if (this.onChangesDetected) {
            this.onChangesDetected(changes);
          }
        } else {
          this.logger.info('No environment changes detected');
        }
      } else {
        this.logger.info('First environment snapshot captured', {
          software_count: newSnapshot.installed_software.length,
          service_count: newSnapshot.services.length,
          adapter_count: newSnapshot.network.adapters.length,
        });
      }

      // Persist
      this.currentSnapshot = newSnapshot;
      this.saveSnapshot(newSnapshot);

      this.logger.info('Environment scan complete', {
        duration_ms: newSnapshot.collection_duration_ms,
        snapshot_id: newSnapshot.snapshot_id,
      });

      return newSnapshot;
    } finally {
      this.isScanning = false;
    }
  }

  /**
   * Run an incremental scan for a single section, diff against current snapshot.
   */
  async runIncrementalCheck(section: string): Promise<void> {
    if (!this.currentSnapshot) return;
    if (this.isScanning) return;

    try {
      const newData = await this.discovery.discoverSection(section);
      if (!newData) return;

      // Build a minimal "new snapshot" with just the updated section
      const partialSnapshot = { ...this.currentSnapshot };
      switch (section) {
        case 'services':
          partialSnapshot.services = newData;
          break;
        case 'network':
          partialSnapshot.network = newData;
          break;
        case 'installed_software':
          partialSnapshot.installed_software = newData;
          break;
        case 'local_accounts':
          partialSnapshot.local_accounts = newData;
          break;
        default:
          return;
      }

      const changes = this.diffSection(section, this.currentSnapshot, partialSnapshot);
      if (changes.length > 0) {
        this.logger.info('Incremental environment changes detected', { section, count: changes.length });

        const journalEntry: ChangeJournalEntry = {
          journal_id: crypto.randomBytes(8).toString('hex'),
          snapshot_id: this.currentSnapshot.snapshot_id,
          timestamp: new Date().toISOString(),
          scan_type: 'incremental',
          changes,
        };
        this.appendToJournal(journalEntry);

        // Update current snapshot with new data
        switch (section) {
          case 'services':
            this.currentSnapshot.services = newData;
            break;
          case 'network':
            this.currentSnapshot.network = newData;
            break;
          case 'installed_software':
            this.currentSnapshot.installed_software = newData;
            break;
          case 'local_accounts':
            this.currentSnapshot.local_accounts = newData;
            break;
        }
        this.saveSnapshot(this.currentSnapshot);

        if (this.onChangesDetected) {
          this.onChangesDetected(changes);
        }
      }
    } catch (err) {
      this.logger.warn('Incremental environment check failed', { section, error: err });
    }
  }

  // ============================
  // DIFFING ENGINE
  // ============================

  private diffSnapshots(previous: EnvironmentSnapshot, current: EnvironmentSnapshot): EnvironmentChangeEvent[] {
    const changes: EnvironmentChangeEvent[] = [];

    // Hardware - scalar comparisons
    changes.push(...this.diffObject('hardware.cpu', previous.hardware.cpu, current.hardware.cpu));
    changes.push(...this.diffObject('hardware.memory', previous.hardware.memory, current.hardware.memory));
    changes.push(...this.diffObject('hardware.motherboard', previous.hardware.motherboard, current.hardware.motherboard));
    changes.push(...this.diffArray('hardware.gpu', previous.hardware.gpu, current.hardware.gpu, g => g.name));
    changes.push(...this.diffArray('hardware.disks', previous.hardware.disks, current.hardware.disks, d => d.model + '|' + d.serial_number));

    // OS - scalar
    changes.push(...this.diffObject('operating_system', previous.operating_system, current.operating_system,
      ['uptime_hours', 'last_boot', 'pending_reboot', 'pending_reboot_reasons']));

    // Software - array
    changes.push(...this.diffArray('installed_software', previous.installed_software, current.installed_software,
      s => s.name + '|' + s.architecture));

    // Network adapters - array
    changes.push(...this.diffArray('network.adapters', previous.network.adapters, current.network.adapters,
      a => a.mac_address || a.name));
    // Network extended - scalar
    changes.push(...this.diffObject('network.proxy_settings', previous.network.proxy_settings, current.network.proxy_settings));
    changes.push(...this.diffScalar('network', 'dns_suffix', previous.network.dns_suffix, current.network.dns_suffix));

    // AD
    if (previous.active_directory && current.active_directory) {
      changes.push(...this.diffObject('active_directory', previous.active_directory, current.active_directory));
    } else if (!previous.active_directory && current.active_directory) {
      changes.push(this.createChange('active_directory', 'active_directory', 'added', null, 'Joined domain', `Joined domain: ${current.active_directory.domain_fqdn}`));
    } else if (previous.active_directory && !current.active_directory) {
      changes.push(this.createChange('active_directory', 'active_directory', 'removed', 'Was domain-joined', null, `Left domain: ${previous.active_directory.domain_fqdn}`));
    }

    // Local accounts - array
    changes.push(...this.diffArray('local_accounts', previous.local_accounts, current.local_accounts, u => u.sid));

    // Services - array
    changes.push(...this.diffArray('services', previous.services, current.services, s => s.name));

    // Printers & Shares - arrays
    changes.push(...this.diffArray('printers_and_shares.printers', previous.printers_and_shares.printers, current.printers_and_shares.printers, p => p.name));
    changes.push(...this.diffArray('printers_and_shares.shares', previous.printers_and_shares.shares, current.printers_and_shares.shares, s => s.name));

    // Server roles
    if (previous.server_roles_features && current.server_roles_features) {
      changes.push(...this.diffArray('server_roles_features', previous.server_roles_features, current.server_roles_features, r => r.name));
    }

    return changes;
  }

  /**
   * Diff a single section from two snapshots (for incremental checks).
   */
  private diffSection(section: string, previous: EnvironmentSnapshot, current: EnvironmentSnapshot): EnvironmentChangeEvent[] {
    switch (section) {
      case 'services':
        return this.diffArray('services', previous.services, current.services, s => s.name);
      case 'network':
        return [
          ...this.diffArray('network.adapters', previous.network.adapters, current.network.adapters, a => a.mac_address || a.name),
          ...this.diffObject('network.proxy_settings', previous.network.proxy_settings, current.network.proxy_settings),
        ];
      case 'installed_software':
        return this.diffArray('installed_software', previous.installed_software, current.installed_software, s => s.name + '|' + s.architecture);
      case 'local_accounts':
        return this.diffArray('local_accounts', previous.local_accounts, current.local_accounts, u => u.sid);
      default:
        return [];
    }
  }

  /**
   * Compare two objects field by field. Emits changes for each differing leaf value.
   * ignoreFields: fields to skip (e.g., volatile values like uptime).
   */
  private diffObject(sectionPath: string, prev: any, curr: any, ignoreFields?: string[]): EnvironmentChangeEvent[] {
    const changes: EnvironmentChangeEvent[] = [];
    if (!prev || !curr) return changes;

    const ignore = new Set(ignoreFields || []);
    const allKeys = new Set([...Object.keys(prev), ...Object.keys(curr)]);

    for (const key of allKeys) {
      if (ignore.has(key)) continue;
      const prevVal = prev[key];
      const currVal = curr[key];

      // Skip arrays and objects for now (handled separately)
      if (Array.isArray(prevVal) || Array.isArray(currVal)) continue;
      if (typeof prevVal === 'object' && prevVal !== null) continue;

      if (String(prevVal) !== String(currVal)) {
        const fieldPath = `${sectionPath}.${key}`;
        const summary = this.generateFieldChangeSummary(sectionPath, key, prevVal, currVal);
        changes.push(this.createChange(sectionPath.split('.')[0], fieldPath, 'modified', prevVal, currVal, summary));
      }
    }

    return changes;
  }

  /**
   * Compare a single scalar field.
   */
  private diffScalar(section: string, field: string, prev: any, curr: any): EnvironmentChangeEvent[] {
    if (String(prev) !== String(curr)) {
      return [this.createChange(section, `${section}.${field}`, 'modified', prev, curr,
        `${field} changed from "${prev}" to "${curr}"`)];
    }
    return [];
  }

  /**
   * Compare two arrays using a key function to match items.
   */
  private diffArray<T extends Record<string, any>>(
    sectionPath: string,
    prev: T[],
    curr: T[],
    keyFn: (item: T) => string,
  ): EnvironmentChangeEvent[] {
    const changes: EnvironmentChangeEvent[] = [];
    const section = sectionPath.split('.')[0];

    const prevMap = new Map<string, T>();
    const currMap = new Map<string, T>();
    for (const item of (prev || [])) prevMap.set(keyFn(item), item);
    for (const item of (curr || [])) currMap.set(keyFn(item), item);

    // Added items
    for (const [key, item] of currMap) {
      if (!prevMap.has(key)) {
        const summary = this.generateAddedSummary(sectionPath, item);
        changes.push(this.createChange(section, `${sectionPath}[${key}]`, 'added', null, item, summary));
      }
    }

    // Removed items
    for (const [key, item] of prevMap) {
      if (!currMap.has(key)) {
        const summary = this.generateRemovedSummary(sectionPath, item);
        changes.push(this.createChange(section, `${sectionPath}[${key}]`, 'removed', item, null, summary));
      }
    }

    // Modified items — compare field by field
    for (const [key, currItem] of currMap) {
      const prevItem = prevMap.get(key);
      if (!prevItem) continue;

      for (const field of Object.keys(currItem)) {
        const prevVal = prevItem[field];
        const currVal = currItem[field];

        // Skip arrays/objects and unchanged values
        if (Array.isArray(prevVal) || typeof prevVal === 'object') continue;
        if (String(prevVal) === String(currVal)) continue;

        // Skip volatile fields per section
        if (this.isVolatileField(sectionPath, field)) continue;

        const displayName = this.getItemDisplayName(sectionPath, currItem);
        const summary = `${displayName}: ${field} changed from "${prevVal}" to "${currVal}"`;
        changes.push(this.createChange(section, `${sectionPath}[${key}].${field}`, 'modified', prevVal, currVal, summary));
      }
    }

    return changes;
  }

  // ============================
  // SUMMARY GENERATION
  // ============================

  private generateFieldChangeSummary(section: string, field: string, prev: any, curr: any): string {
    // Readable section names
    const readable: Record<string, string> = {
      'hardware.cpu': 'CPU',
      'hardware.memory': 'Memory',
      'hardware.motherboard': 'Motherboard',
      'operating_system': 'OS',
      'network.proxy_settings': 'Proxy',
    };
    const prefix = readable[section] || section;
    return `${prefix}: ${field} changed from "${prev}" to "${curr}"`;
  }

  private generateAddedSummary(section: string, item: any): string {
    switch (section) {
      case 'installed_software':
        return `Software installed: ${item.name} ${item.version}${item.publisher ? ` (${item.publisher})` : ''}`;
      case 'services':
        return `Service added: ${item.display_name || item.name}`;
      case 'local_accounts':
        return `Local account added: ${item.name}${item.is_local_admin ? ' (admin)' : ''}`;
      case 'network.adapters':
        return `Network adapter added: ${item.name}`;
      case 'printers_and_shares.printers':
        return `Printer added: ${item.name}`;
      case 'printers_and_shares.shares':
        return `Share added: ${item.name} (${item.path})`;
      case 'hardware.gpu':
        return `GPU added: ${item.name}`;
      case 'hardware.disks':
        return `Disk added: ${item.model} (${item.capacity_gb} GB)`;
      case 'server_roles_features':
        return `Role/Feature installed: ${item.display_name || item.name}`;
      default:
        return `Added: ${JSON.stringify(item).substring(0, 100)}`;
    }
  }

  private generateRemovedSummary(section: string, item: any): string {
    switch (section) {
      case 'installed_software':
        return `Software removed: ${item.name} ${item.version}`;
      case 'services':
        return `Service removed: ${item.display_name || item.name}`;
      case 'local_accounts':
        return `Local account removed: ${item.name}`;
      case 'network.adapters':
        return `Network adapter removed: ${item.name}`;
      case 'printers_and_shares.printers':
        return `Printer removed: ${item.name}`;
      case 'printers_and_shares.shares':
        return `Share removed: ${item.name}`;
      case 'hardware.gpu':
        return `GPU removed: ${item.name}`;
      case 'hardware.disks':
        return `Disk removed: ${item.model}`;
      case 'server_roles_features':
        return `Role/Feature removed: ${item.display_name || item.name}`;
      default:
        return `Removed: ${JSON.stringify(item).substring(0, 100)}`;
    }
  }

  private getItemDisplayName(section: string, item: any): string {
    switch (section) {
      case 'installed_software': return item.name;
      case 'services': return item.display_name || item.name;
      case 'local_accounts': return item.name;
      case 'network.adapters': return item.name;
      case 'printers_and_shares.printers': return item.name;
      case 'printers_and_shares.shares': return item.name;
      default: return item.name || item.display_name || 'Unknown';
    }
  }

  private isVolatileField(section: string, field: string): boolean {
    const volatileFields: Record<string, Set<string>> = {
      'services': new Set(['pid']),
      'local_accounts': new Set(['last_logon']),
    };
    return volatileFields[section]?.has(field) || false;
  }

  // ============================
  // CHANGE EVENT FACTORY
  // ============================

  private createChange(
    section: string,
    fieldPath: string,
    changeType: 'added' | 'removed' | 'modified',
    prevValue: any,
    newValue: any,
    summary: string,
  ): EnvironmentChangeEvent {
    return {
      change_id: crypto.randomBytes(8).toString('hex'),
      timestamp: new Date().toISOString(),
      section,
      field_path: fieldPath,
      change_type: changeType,
      previous_value: prevValue,
      new_value: newValue,
      summary,
    };
  }

  // ============================
  // JOURNAL MANAGEMENT
  // ============================

  private appendToJournal(entry: ChangeJournalEntry): void {
    try {
      const journal = this.loadJournal();
      journal.entries.push(entry);

      // Prune if needed
      this.pruneJournal(journal);

      this.saveJournal(journal);
    } catch (err) {
      this.logger.error('Failed to append to environment journal', err);
    }
  }

  private pruneJournal(journal: EnvironmentJournalData): void {
    const cutoff = Date.now() - (JOURNAL_MAX_AGE_DAYS * 24 * 60 * 60 * 1000);

    // Remove entries older than max age
    journal.entries = journal.entries.filter(e => new Date(e.timestamp).getTime() > cutoff);

    // Cap total entries
    if (journal.entries.length > JOURNAL_MAX_ENTRIES) {
      journal.entries = journal.entries.slice(-JOURNAL_MAX_ENTRIES);
    }
  }

  // ============================
  // PERSISTENCE
  // ============================

  private loadSnapshot(): EnvironmentSnapshot | null {
    try {
      if (fs.existsSync(this.snapshotPath)) {
        const raw = fs.readFileSync(this.snapshotPath, 'utf8');
        return JSON.parse(raw);
      }
    } catch (err) {
      this.logger.warn('Failed to load environment snapshot', err);
    }
    return null;
  }

  private saveSnapshot(snapshot: EnvironmentSnapshot): void {
    try {
      fs.writeFileSync(this.snapshotPath, JSON.stringify(snapshot, null, 2), 'utf8');
    } catch (err) {
      this.logger.error('Failed to save environment snapshot', err);
    }
  }

  private loadJournal(): EnvironmentJournalData {
    try {
      if (fs.existsSync(this.journalPath)) {
        const raw = fs.readFileSync(this.journalPath, 'utf8');
        return JSON.parse(raw);
      }
    } catch (err) {
      this.logger.warn('Failed to load environment journal', err);
    }
    return { entries: [], version: '1' };
  }

  private saveJournal(journal: EnvironmentJournalData): void {
    try {
      fs.writeFileSync(this.journalPath, JSON.stringify(journal, null, 2), 'utf8');
    } catch (err) {
      this.logger.error('Failed to save environment journal', err);
    }
  }

  // ============================
  // PUBLIC ACCESSORS
  // ============================

  getCurrentSnapshot(): EnvironmentSnapshot | null {
    return this.currentSnapshot;
  }

  getChangesSince(isoTimestamp: string): ChangeJournalEntry[] {
    const journal = this.loadJournal();
    const since = new Date(isoTimestamp).getTime();
    return journal.entries.filter(e => new Date(e.timestamp).getTime() > since);
  }

  getJournalSummary(lastN: number = 50): ChangeJournalEntry[] {
    const journal = this.loadJournal();
    return journal.entries.slice(-lastN);
  }
}
