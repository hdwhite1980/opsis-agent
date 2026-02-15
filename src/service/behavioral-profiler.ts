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

export interface MonthlyProfileBucket {
  metric_key: string;
  month: number;          // 0-11
  sample_count: number;
  mean_deviation: number; // Deviation from the overall mean
  m2: number;
  last_updated: string;
}

interface OverallMeanTracker {
  mean: number;
  sampleCount: number;
  m2: number;
}

// Composite key for the in-memory profile cache
function bucketKey(metricKey: string, hour: number, isWeekday: number): string {
  return `${metricKey}|${hour}|${isWeekday}`;
}

function monthlyKey(metricKey: string, month: number): string {
  return `${metricKey}|month:${month}`;
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

  // Monthly seasonality: 12 buckets per metric tracking deviation from overall mean
  private monthlyProfiles: Map<string, MonthlyProfileBucket> = new Map();
  private overallMeans: Map<string, OverallMeanTracker> = new Map();

  private flushInterval: NodeJS.Timeout | null = null;

  private readonly MIN_SAMPLES = 50;
  private readonly Z_THRESHOLD = 2.5;
  private readonly FLUSH_INTERVAL_MS = 300_000; // 5 minutes
  private readonly MAX_TRACKED_PROCESSES = 20;

  // Suppression tracking for dashboard reporting
  private suppressedThisMonth: number = 0;
  private suppressedTotal: number = 0;
  private suppressedByMetric: Map<string, number> = new Map();
  private currentMonth: string = '';
  private firstBucketSeen: string = '';

  // Core system metrics used for learning progress calculation
  private static readonly CORE_METRICS = ['system:cpu', 'system:memory', 'system:disk:C'];
  private static readonly LEARNING_DAYS_TARGET = 7;
  private static readonly ACTIVE_COVERAGE_THRESHOLD = 0.70;

  // File paths for persistence
  private readonly profilesPath: string;
  private readonly processFreqPath: string;
  private readonly statsPath: string;
  private readonly monthlyProfilesPath: string;

  constructor(dataDir: string, logger: Logger) {
    this.dataDir = dataDir;
    this.logger = logger;
    this.profilesPath = path.join(dataDir, 'behavioral-profiles.json');
    this.processFreqPath = path.join(dataDir, 'process-frequency.json');
    this.statsPath = path.join(dataDir, 'profiler-stats.json');
    this.monthlyProfilesPath = path.join(dataDir, 'monthly-profiles.json');
    this.currentMonth = new Date().toISOString().slice(0, 7); // "2026-02"

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

      // Load monthly profiles
      if (fs.existsSync(this.monthlyProfilesPath)) {
        const raw = fs.readFileSync(this.monthlyProfilesPath, 'utf8');
        const data = JSON.parse(raw);
        if (data.monthlyBuckets) {
          for (const bucket of data.monthlyBuckets) {
            const key = monthlyKey(bucket.metric_key, bucket.month);
            this.monthlyProfiles.set(key, bucket);
          }
        }
        if (data.overallMeans) {
          for (const [metricKey, tracker] of Object.entries(data.overallMeans)) {
            this.overallMeans.set(metricKey, tracker as OverallMeanTracker);
          }
        }
      }

      // Load suppression stats
      if (fs.existsSync(this.statsPath)) {
        const raw = fs.readFileSync(this.statsPath, 'utf8');
        const stats = JSON.parse(raw);
        this.suppressedTotal = stats.suppressed_total || 0;
        this.firstBucketSeen = stats.first_bucket_seen || '';

        // If same month, restore monthly counters; otherwise start fresh
        if (stats.current_month === this.currentMonth) {
          this.suppressedThisMonth = stats.suppressed_this_month || 0;
          if (stats.suppressed_by_metric) {
            for (const [metric, count] of Object.entries(stats.suppressed_by_metric)) {
              this.suppressedByMetric.set(metric, count as number);
            }
          }
        }
      }

      this.logger.info('Behavioral profiles loaded', {
        profile_buckets: this.profiles.size,
        tracked_processes: this.processFrequency.size,
        suppressed_total: this.suppressedTotal,
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

    // Track when profiling first started (for learning day calculation)
    if (!this.firstBucketSeen) {
      this.firstBucketSeen = new Date().toISOString();
    }

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

    // Update overall mean and monthly deviation bucket
    this.updateOverallMean(metricKey, value);
    this.updateMonthlyBucket(metricKey, value);
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

    // Monthly seasonality fallback — check if value matches the monthly deviation pattern
    const monthlyResult = this.checkMonthlyFallback(metricKey, value);
    if (monthlyResult) return monthlyResult;

    // Anomalous for both day types and monthly — genuinely abnormal
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

  /**
   * Record that a signal was suppressed by the behavioral profile.
   * Called by SystemMonitor when isProfileAnomalous returns false.
   */
  recordSuppression(metricKey: string): void {
    // Monthly rotation: if the month changed, reset monthly counters
    const now = new Date().toISOString().slice(0, 7);
    if (now !== this.currentMonth) {
      this.suppressedThisMonth = 0;
      this.suppressedByMetric.clear();
      this.currentMonth = now;
    }

    this.suppressedThisMonth++;
    this.suppressedTotal++;
    this.suppressedByMetric.set(metricKey, (this.suppressedByMetric.get(metricKey) || 0) + 1);
  }

  /**
   * Get a dashboard-friendly summary of profiler status.
   * Included in the telemetry heartbeat for server/dashboard display.
   */
  getDashboardSummary(): Record<string, any> {
    // Compute learning coverage for core system metrics
    let weekdayReady = 0;
    let weekendReady = 0;
    const weekdayTotal = BehavioralProfiler.CORE_METRICS.length * 24; // 3 metrics × 24 hours
    const weekendTotal = weekdayTotal;

    for (const metric of BehavioralProfiler.CORE_METRICS) {
      for (let hour = 0; hour < 24; hour++) {
        const wdKey = bucketKey(metric, hour, 1);
        const wdBucket = this.profiles.get(wdKey);
        if (wdBucket && wdBucket.sample_count >= this.MIN_SAMPLES) weekdayReady++;

        const weKey = bucketKey(metric, hour, 0);
        const weBucket = this.profiles.get(weKey);
        if (weBucket && weBucket.sample_count >= this.MIN_SAMPLES) weekendReady++;
      }
    }

    const weekdayCoverage = weekdayTotal > 0 ? weekdayReady / weekdayTotal : 0;
    const weekendCoverage = weekendTotal > 0 ? weekendReady / weekendTotal : 0;
    const status = weekdayCoverage >= BehavioralProfiler.ACTIVE_COVERAGE_THRESHOLD ? 'active' : 'learning';

    // Learning day: days since first profile data appeared
    let learningDay = 0;
    const firstSeen = this.firstBucketSeen || this.findEarliestBucket();
    if (firstSeen) {
      learningDay = Math.max(1, Math.ceil((Date.now() - new Date(firstSeen).getTime()) / (1000 * 60 * 60 * 24)));
      learningDay = Math.min(learningDay, BehavioralProfiler.LEARNING_DAYS_TARGET);
      if (!this.firstBucketSeen) this.firstBucketSeen = firstSeen;
    }

    // Top suppressed metrics this month (top 3)
    const topSuppressed = [...this.suppressedByMetric.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([metric, count]) => ({ metric, count }));

    return {
      status,
      learning_progress: Math.round(weekdayCoverage * 100) / 100,
      learning_day: learningDay,
      learning_days_target: BehavioralProfiler.LEARNING_DAYS_TARGET,
      weekday_coverage: Math.round(weekdayCoverage * 100) / 100,
      weekend_coverage: Math.round(weekendCoverage * 100) / 100,
      total_buckets: weekdayTotal + weekendTotal,
      ready_buckets: weekdayReady + weekendReady,
      suppressed_this_month: this.suppressedThisMonth,
      suppressed_total: this.suppressedTotal,
      top_suppressed_metrics: topSuppressed,
    };
  }

  /**
   * Find the earliest last_updated timestamp across all profile buckets.
   */
  private findEarliestBucket(): string {
    let earliest = '';
    for (const bucket of this.profiles.values()) {
      if (!earliest || bucket.last_updated < earliest) {
        earliest = bucket.last_updated;
      }
    }
    return earliest;
  }

  /**
   * Update the overall (all-time, all-buckets) running mean for a metric.
   */
  private updateOverallMean(metricKey: string, value: number): void {
    let tracker = this.overallMeans.get(metricKey);
    if (!tracker) {
      tracker = { mean: 0, sampleCount: 0, m2: 0 };
    }
    tracker.sampleCount++;
    const delta = value - tracker.mean;
    tracker.mean += delta / tracker.sampleCount;
    const delta2 = value - tracker.mean;
    tracker.m2 += delta * delta2;
    this.overallMeans.set(metricKey, tracker);
  }

  /**
   * Update the monthly deviation bucket. Tracks how much the current month's
   * values deviate from the overall mean (e.g. patch Tuesday spikes in Feb).
   */
  private updateMonthlyBucket(metricKey: string, value: number): void {
    const month = new Date().getMonth(); // 0-11
    const key = monthlyKey(metricKey, month);
    const overall = this.overallMeans.get(metricKey);
    if (!overall || overall.sampleCount < 10) return; // Need baseline first

    const deviation = value - overall.mean;

    let bucket = this.monthlyProfiles.get(key);
    if (!bucket) {
      bucket = {
        metric_key: metricKey,
        month,
        sample_count: 0,
        mean_deviation: 0,
        m2: 0,
        last_updated: new Date().toISOString()
      };
    }

    // Welford's on the deviation values
    bucket.sample_count++;
    const d1 = deviation - bucket.mean_deviation;
    bucket.mean_deviation += d1 / bucket.sample_count;
    const d2 = deviation - bucket.mean_deviation;
    bucket.m2 += d1 * d2;
    bucket.last_updated = new Date().toISOString();

    this.monthlyProfiles.set(key, bucket);
  }

  /**
   * Check if a value is within the expected monthly deviation pattern.
   * Used as a final fallback after cross-day check fails.
   */
  private checkMonthlyFallback(metricKey: string, value: number): AnomalyResult | null {
    const month = new Date().getMonth();
    const key = monthlyKey(metricKey, month);
    const monthBucket = this.monthlyProfiles.get(key);
    const overall = this.overallMeans.get(metricKey);

    if (!monthBucket || monthBucket.sample_count < 30 || !overall) return null;

    // Expected value = overallMean + monthly deviation
    const expected = overall.mean + monthBucket.mean_deviation;
    const variance = monthBucket.sample_count > 1 ? monthBucket.m2 / monthBucket.sample_count : 0;
    const stddev = Math.sqrt(variance);
    if (stddev < 0.001) return null;

    const zScore = (value - expected) / stddev;
    if (Math.abs(zScore) <= this.Z_THRESHOLD) {
      return {
        anomalous: false,
        reason: 'within_normal',
        current_value: value,
        profile: {
          mean: Math.round(expected * 100) / 100,
          stddev: Math.round(stddev * 100) / 100,
          z_score: Math.round(zScore * 100) / 100,
          sample_count: monthBucket.sample_count,
          time_bucket: `month ${month} (monthly fallback)`
        }
      };
    }

    return null;
  }

  private rebuildTopProcesses(): void {
    this.cachedTopProcesses = [...this.processFrequency.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, this.MAX_TRACKED_PROCESSES)
      .map(([name]) => name);
  }

  /**
   * Flush all dirty profile buckets and stats to JSON files on disk.
   */
  async flush(): Promise<void> {
    try {
      // Flush profile buckets — write all profiles (not just dirty ones) for consistency
      if (this.dirty.size > 0 || this.profiles.size > 0) {
        const allBuckets = [...this.profiles.values()];
        fs.writeFileSync(this.profilesPath, JSON.stringify(allBuckets), 'utf8');
      }

      // Flush process frequency
      if (this.processFrequency.size > 0) {
        const freqObj: Record<string, number> = {};
        for (const [name, count] of this.processFrequency.entries()) {
          freqObj[name] = count;
        }
        fs.writeFileSync(this.processFreqPath, JSON.stringify(freqObj), 'utf8');
      }

      // Flush monthly profiles
      if (this.monthlyProfiles.size > 0) {
        const overallObj: Record<string, OverallMeanTracker> = {};
        for (const [key, tracker] of this.overallMeans.entries()) {
          overallObj[key] = tracker;
        }
        const monthlyData = {
          monthlyBuckets: [...this.monthlyProfiles.values()],
          overallMeans: overallObj
        };
        fs.writeFileSync(this.monthlyProfilesPath, JSON.stringify(monthlyData), 'utf8');
      }

      // Flush suppression stats
      const statsObj: Record<string, any> = {
        suppressed_total: this.suppressedTotal,
        suppressed_this_month: this.suppressedThisMonth,
        current_month: this.currentMonth,
        first_bucket_seen: this.firstBucketSeen,
        suppressed_by_metric: {} as Record<string, number>,
      };
      for (const [metric, count] of this.suppressedByMetric.entries()) {
        statsObj.suppressed_by_metric[metric] = count;
      }
      fs.writeFileSync(this.statsPath, JSON.stringify(statsObj), 'utf8');

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
