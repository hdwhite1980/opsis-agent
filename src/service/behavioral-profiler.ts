/**
 * OPSIS Agent Behavioral Profiler
 *
 * Learns what "normal" looks like for each metric across time-of-day and
 * day-of-week using Welford's online algorithm for streaming mean/variance.
 * Used by the detection engine to suppress false positives — e.g. Chrome
 * using 1.5GB at 2pm on a Tuesday is normal if the profile says so.
 *
 * Time bucketing: 24 hours × 2 (weekday/weekend) = 48 buckets per metric.
 * Per-process tracking: Top 20 most frequently seen processes get individual
 * CPU and memory profiles.
 *
 * Persistence: JSON files in the data directory (profiles.json, process-frequency.json).
 */

import * as fs from 'fs';
import * as path from 'path';
import { Logger } from '../common/logger';

export interface ProfileBucket {
  metric_key: string;
  hour_of_day: number;
  is_weekday: number;
  sample_count: number;
  mean: number;
  m2: number;
  min_value: number;
  max_value: number;
  last_updated: string;
}

export interface AnomalyResult {
  anomalous: boolean;
  reason: 'anomalous' | 'within_normal' | 'insufficient_data';
  current_value: number;
  profile?: {
    mean: number;
    stddev: number;
    z_score: number;
    sample_count: number;
    time_bucket: string;
  };
}

export interface ProcessSnapshot {
  name: string;
  cpu: number;
  memoryMB: number;
}

// Composite key for the in-memory profile cache
function bucketKey(metricKey: string, hour: number, isWeekday: number): string {
  return `${metricKey}|${hour}|${isWeekday}`;
}

function getCurrentBucket(): { hour: number; isWeekday: number } {
  const now = new Date();
  const day = now.getDay(); // 0=Sun, 6=Sat
  return {
    hour: now.getHours(),
    isWeekday: (day >= 1 && day <= 5) ? 1 : 0,
  };
}

export class BehavioralProfiler {
  private logger: Logger;
  private dataDir: string;

  // In-memory profile cache — keyed by "metricKey|hour|isWeekday"
  private profiles: Map<string, ProfileBucket> = new Map();
  // Track which buckets have been modified since last flush
  private dirty: Set<string> = new Set();

  // Process frequency tracking
  private processFrequency: Map<string, number> = new Map();
  private cachedTopProcesses: string[] = [];

  private flushInterval: NodeJS.Timeout | null = null;

  private readonly MIN_SAMPLES = 50;
  private readonly Z_THRESHOLD = 2.5;
  private readonly FLUSH_INTERVAL_MS = 300_000; // 5 minutes
  private readonly MAX_TRACKED_PROCESSES = 20;

  // File paths for persistence
  private readonly profilesPath: string;
  private readonly processFreqPath: string;

  constructor(dataDir: string, logger: Logger) {
    this.dataDir = dataDir;
    this.logger = logger;
    this.profilesPath = path.join(dataDir, 'behavioral-profiles.json');
    this.processFreqPath = path.join(dataDir, 'process-frequency.json');

    // Load existing profiles from disk on startup
    this.loadProfiles();

    // Schedule periodic flush to disk
    this.flushInterval = setInterval(() => {
      this.flush().catch(err => {
        this.logger.error('Failed to flush behavioral profiles', err);
      });
    }, this.FLUSH_INTERVAL_MS);
  }

  /**
   * Load existing profile data from JSON files into memory.
   */
  private loadProfiles(): void {
    try {
      if (fs.existsSync(this.profilesPath)) {
        const raw = fs.readFileSync(this.profilesPath, 'utf8');
        const buckets: ProfileBucket[] = JSON.parse(raw);
        for (const bucket of buckets) {
          const key = bucketKey(bucket.metric_key, bucket.hour_of_day, bucket.is_weekday);
          this.profiles.set(key, bucket);
        }
      }

      if (fs.existsSync(this.processFreqPath)) {
        const raw = fs.readFileSync(this.processFreqPath, 'utf8');
        const freq: Record<string, number> = JSON.parse(raw);
        for (const [name, count] of Object.entries(freq)) {
          this.processFrequency.set(name, count);
        }
        this.rebuildTopProcesses();
      }

      this.logger.info('Behavioral profiles loaded', {
        profile_buckets: this.profiles.size,
        tracked_processes: this.processFrequency.size,
      });
    } catch (error) {
      this.logger.warn('Could not load behavioral profiles (files may not exist yet)', error);
    }
  }

  /**
   * Record a metric sample for the current time bucket.
   * Uses Welford's online algorithm for streaming mean/variance.
   * This is synchronous — does not block the monitoring loop.
   */
  recordSample(metricKey: string, value: number): void {
    if (!isFinite(value)) return;

    const { hour, isWeekday } = getCurrentBucket();
    const key = bucketKey(metricKey, hour, isWeekday);

    let bucket = this.profiles.get(key);
    if (!bucket) {
      bucket = {
        metric_key: metricKey,
        hour_of_day: hour,
        is_weekday: isWeekday,
        sample_count: 0,
        mean: 0,
        m2: 0,
        min_value: value,
        max_value: value,
        last_updated: new Date().toISOString(),
      };
      this.profiles.set(key, bucket);
    }

    // Welford's online algorithm
    bucket.sample_count++;
    const delta = value - bucket.mean;
    bucket.mean += delta / bucket.sample_count;
    const delta2 = value - bucket.mean;
    bucket.m2 += delta * delta2;

    bucket.min_value = Math.min(bucket.min_value, value);
    bucket.max_value = Math.max(bucket.max_value, value);
    bucket.last_updated = new Date().toISOString();

    this.dirty.add(key);
  }

  /**
   * Record a snapshot of the top processes.
   * Updates process frequency counts and records per-process metrics
   * for the top 20 most frequently seen processes.
   */
  recordProcessSnapshot(processes: ProcessSnapshot[]): void {
    // Update frequency counts
    for (const proc of processes) {
      const name = proc.name.toLowerCase();
      this.processFrequency.set(name, (this.processFrequency.get(name) || 0) + 1);
    }

    // Rebuild top processes list periodically (every snapshot is fine — it's cheap)
    this.rebuildTopProcesses();

    // Record per-process metrics for top processes only
    const topSet = new Set(this.cachedTopProcesses);
    for (const proc of processes) {
      const name = proc.name.toLowerCase();
      if (topSet.has(name)) {
        if (isFinite(proc.cpu) && proc.cpu > 0) {
          this.recordSample(`process:${name}:cpu`, proc.cpu);
        }
        if (isFinite(proc.memoryMB) && proc.memoryMB > 0) {
          this.recordSample(`process:${name}:memory`, proc.memoryMB);
        }
      }
    }
  }

  /**
   * Evaluate a value against a single profile bucket.
   * Returns null if the bucket has insufficient data.
   */
  private evaluateBucket(bucket: ProfileBucket, value: number, hour: number, isWeekday: number): AnomalyResult | null {
    if (bucket.sample_count < this.MIN_SAMPLES) return null;

    const variance = bucket.sample_count > 1 ? bucket.m2 / bucket.sample_count : 0;
    const stddev = Math.sqrt(variance);
    const timeBucket = `${isWeekday ? 'weekday' : 'weekend'} hour ${hour}`;

    // If stddev is effectively zero, any deviation is anomalous
    if (stddev < 0.001) {
      const isAnomaly = Math.abs(value - bucket.mean) > 0.5;
      return {
        anomalous: isAnomaly,
        reason: isAnomaly ? 'anomalous' : 'within_normal',
        current_value: value,
        profile: {
          mean: bucket.mean,
          stddev,
          z_score: stddev > 0 ? (value - bucket.mean) / stddev : 0,
          sample_count: bucket.sample_count,
          time_bucket: timeBucket,
        },
      };
    }

    const zScore = (value - bucket.mean) / stddev;
    const anomalous = zScore > this.Z_THRESHOLD;

    return {
      anomalous,
      reason: anomalous ? 'anomalous' : 'within_normal',
      current_value: value,
      profile: {
        mean: Math.round(bucket.mean * 100) / 100,
        stddev: Math.round(stddev * 100) / 100,
        z_score: Math.round(zScore * 100) / 100,
        sample_count: bucket.sample_count,
        time_bucket: timeBucket,
      },
    };
  }

  /**
   * Check if a metric value is anomalous for the current time bucket.
   *
   * Cross-day fallback: if the value looks anomalous for the current day type
   * (e.g. weekend), the opposite day type's profile for the same hour is checked.
   * If the value is within normal for that profile, it's suppressed — the user
   * is likely just working on a weekend (or idle on a weekday).
   */
  isAnomalous(metricKey: string, value: number): AnomalyResult {
    const { hour, isWeekday } = getCurrentBucket();

    // Primary bucket — current day type
    const primaryKey = bucketKey(metricKey, hour, isWeekday);
    const primaryBucket = this.profiles.get(primaryKey);

    if (!primaryBucket || primaryBucket.sample_count < this.MIN_SAMPLES) {
      return {
        anomalous: false,
        reason: 'insufficient_data',
        current_value: value,
      };
    }

    const primaryResult = this.evaluateBucket(primaryBucket, value, hour, isWeekday)!;

    // If primary says within_normal, no need to check further
    if (!primaryResult.anomalous) return primaryResult;

    // Primary says anomalous — cross-check the opposite day type for the same hour.
    // e.g. weekend anomaly → check if it's normal for a weekday at this hour.
    const oppositeWeekday = isWeekday ? 0 : 1;
    const fallbackKey = bucketKey(metricKey, hour, oppositeWeekday);
    const fallbackBucket = this.profiles.get(fallbackKey);

    if (fallbackBucket) {
      const fallbackResult = this.evaluateBucket(fallbackBucket, value, hour, oppositeWeekday);

      if (fallbackResult && !fallbackResult.anomalous) {
        // Value is normal for the opposite day type — suppress.
        // Return within_normal but annotate the profile with the fallback context.
        return {
          anomalous: false,
          reason: 'within_normal',
          current_value: value,
          profile: {
            ...fallbackResult.profile!,
            time_bucket: `${oppositeWeekday ? 'weekday' : 'weekend'} hour ${hour} (cross-day fallback)`,
          },
        };
      }
    }

    // Anomalous for both day types (or fallback has insufficient data) — genuinely abnormal
    return primaryResult;
  }

  /**
   * Get the profile for a specific metric and time bucket.
   * Uses current time if hour/weekday not specified.
   */
  getProfile(metricKey: string, hour?: number, weekday?: boolean): ProfileBucket | null {
    const { hour: curHour, isWeekday: curWeekday } = getCurrentBucket();
    const h = hour ?? curHour;
    const w = weekday !== undefined ? (weekday ? 1 : 0) : curWeekday;
    const key = bucketKey(metricKey, h, w);
    return this.profiles.get(key) || null;
  }

  /**
   * Get the top N most frequently seen process names.
   */
  getTopProcesses(limit: number = this.MAX_TRACKED_PROCESSES): string[] {
    return this.cachedTopProcesses.slice(0, limit);
  }

  private rebuildTopProcesses(): void {
    this.cachedTopProcesses = [...this.processFrequency.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, this.MAX_TRACKED_PROCESSES)
      .map(([name]) => name);
  }

  /**
   * Flush all dirty profile buckets to JSON files on disk.
   */
  async flush(): Promise<void> {
    if (this.dirty.size === 0 && this.processFrequency.size === 0) return;

    try {
      // Flush profile buckets — write all profiles (not just dirty ones) for consistency
      const allBuckets = [...this.profiles.values()];
      fs.writeFileSync(this.profilesPath, JSON.stringify(allBuckets), 'utf8');

      // Flush process frequency
      const freqObj: Record<string, number> = {};
      for (const [name, count] of this.processFrequency.entries()) {
        freqObj[name] = count;
      }
      fs.writeFileSync(this.processFreqPath, JSON.stringify(freqObj), 'utf8');

      const flushedCount = this.dirty.size;
      this.dirty.clear();

      if (flushedCount > 0) {
        this.logger.debug('Behavioral profiles flushed', {
          buckets_written: flushedCount,
          total_buckets: this.profiles.size,
        });
      }
    } catch (error) {
      this.logger.error('Failed to flush behavioral profiles to disk', error);
    }
  }

  /**
   * Stop the profiler — flush remaining data and clear intervals.
   */
  stop(): void {
    if (this.flushInterval) {
      clearInterval(this.flushInterval);
      this.flushInterval = null;
    }
  }
}
