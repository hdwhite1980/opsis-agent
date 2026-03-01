// src/service/signal-correlator.ts - Combine multiple active signals for richer decisions

import { Logger } from '../common/logger';
import { SystemSignal } from './system-monitor';

export interface CorrelationResult {
  ruleId: string;
  description: string;
  matchedSignals: string[];
  action: CorrelationAction;
}

export interface CorrelationAction {
  type: 'boost_confidence' | 'suggest_playbook' | 'enrich_escalation';
  confidenceBoost?: number;   // Absolute value to set confidence to (capped by caller's threshold)
  confidenceDelta?: number;   // Additive delta (e.g. +25)
  suggestedPlaybook?: string;
  escalationNote?: string;
}

interface WindowedSignal {
  signal: SystemSignal;
  timestamp: number;
}

interface CompoundRule {
  id: string;
  description: string;
  conditions: (signals: WindowedSignal[]) => string[] | null; // Returns matched signal IDs or null
  action: CorrelationAction;
  cooldownMs: number; // Minimum time between triggers
}

export class SignalCorrelator {
  private logger: Logger;
  private signalWindow: WindowedSignal[] = [];
  private lastTrigger: Map<string, number> = new Map();
  private compoundRules: CompoundRule[];

  private readonly WINDOW_MS = 30 * 60 * 1000; // 30-minute sliding window

  constructor(logger: Logger) {
    this.logger = logger;
    this.compoundRules = this.buildRules();
  }

  /**
   * Record a new signal into the sliding window.
   */
  public recordSignal(signal: SystemSignal): void {
    const now = Date.now();
    this.signalWindow.push({ signal, timestamp: now });

    // Prune signals older than the window
    this.signalWindow = this.signalWindow.filter(
      ws => now - ws.timestamp < this.WINDOW_MS
    );
  }

  /**
   * Check if the newly recorded signal, combined with recent signals,
   * triggers any compound correlation rules.
   */
  public checkCorrelations(signal: SystemSignal): CorrelationResult | null {
    const now = Date.now();

    for (const rule of this.compoundRules) {
      // Check cooldown
      const lastTriggered = this.lastTrigger.get(rule.id) || 0;
      if (now - lastTriggered < rule.cooldownMs) continue;

      const matchedIds = rule.conditions(this.signalWindow);
      if (matchedIds && matchedIds.length > 0) {
        this.lastTrigger.set(rule.id, now);

        this.logger.info('Signal correlation triggered', {
          rule_id: rule.id,
          description: rule.description,
          matched_signals: matchedIds
        });

        return {
          ruleId: rule.id,
          description: rule.description,
          matchedSignals: matchedIds,
          action: rule.action
        };
      }
    }

    return null;
  }

  /**
   * Get a summary of the current signal window for telemetry.
   */
  public getWindowSummary(): { signalCount: number; uniqueCategories: string[]; oldestAge: number } {
    const now = Date.now();
    const categories = new Set(this.signalWindow.map(ws => ws.signal.category));
    const oldest = this.signalWindow.length > 0
      ? now - this.signalWindow[0].timestamp
      : 0;

    return {
      signalCount: this.signalWindow.length,
      uniqueCategories: Array.from(categories),
      oldestAge: oldest
    };
  }

  private buildRules(): CompoundRule[] {
    return [
      // Rule 1: CPU critical + high-CPU process + process has crash history
      {
        id: 'cpu-crashing-process',
        description: 'CPU critical with a high-CPU process that has been crashing',
        cooldownMs: 10 * 60 * 1000,
        conditions: (signals) => {
          const cpuCritical = signals.find(ws =>
            ws.signal.id === 'cpu-critical' || (ws.signal.category === 'performance' && ws.signal.metric === 'cpu' && ws.signal.severity === 'critical')
          );
          const processCpu = signals.find(ws =>
            ws.signal.id?.includes('process-cpu') || (ws.signal.category === 'performance' && ws.signal.metric === 'process_cpu' && (ws.signal.value as number) > 80)
          );
          if (cpuCritical && processCpu) {
            return [cpuCritical.signal.id, processCpu.signal.id];
          }
          return null;
        },
        action: {
          type: 'boost_confidence',
          confidenceBoost: 95,
          suggestedPlaybook: 'targeted-process-kill'
        }
      },

      // Rule 2: Memory critical + process memory growing + crash history
      {
        id: 'memory-leak-crashes',
        description: 'Memory critical with a process consuming excessive memory',
        cooldownMs: 10 * 60 * 1000,
        conditions: (signals) => {
          const memCritical = signals.find(ws =>
            ws.signal.id === 'memory-critical' || (ws.signal.category === 'performance' && ws.signal.metric === 'memory' && ws.signal.severity === 'critical')
          );
          const processMemory = signals.find(ws =>
            ws.signal.id?.includes('process-memory') || (ws.signal.category === 'performance' && ws.signal.metric === 'process_memory')
          );
          if (memCritical && processMemory) {
            return [memCritical.signal.id, processMemory.signal.id];
          }
          return null;
        },
        action: {
          type: 'boost_confidence',
          confidenceBoost: 95,
          suggestedPlaybook: 'targeted-process-restart'
        }
      },

      // Rule 3: Disk critical + Windows Update service running
      {
        id: 'disk-windows-update',
        description: 'Disk critical while Windows Update is actively running',
        cooldownMs: 30 * 60 * 1000,
        conditions: (signals) => {
          const diskCritical = signals.find(ws =>
            ws.signal.id?.includes('disk-critical') || (ws.signal.category === 'storage' && ws.signal.severity === 'critical')
          );
          const wuRunning = signals.find(ws =>
            ws.signal.metadata?.serviceName === 'wuauserv' || ws.signal.id?.includes('windows-update')
          );
          if (diskCritical && wuRunning) {
            return [diskCritical.signal.id, wuRunning.signal.id];
          }
          return null;
        },
        action: {
          type: 'boost_confidence',
          confidenceDelta: 25,
          suggestedPlaybook: 'clear-update-cache-first'
        }
      },

      // Rule 4: Service cascade — a service stops and its parent dependency is also down
      {
        id: 'service-cascade',
        description: 'Multiple dependent services stopped, indicating a cascade failure',
        cooldownMs: 10 * 60 * 1000,
        conditions: (signals) => {
          const stoppedServices = signals.filter(ws =>
            ws.signal.category === 'services' && ws.signal.metric === 'service_status'
          );
          if (stoppedServices.length >= 2) {
            return stoppedServices.map(ws => ws.signal.id);
          }
          return null;
        },
        action: {
          type: 'enrich_escalation',
          escalationNote: 'Multiple services down — possible cascade. Check parent service dependencies before restarting individual services.'
        }
      },

      // Rule 5: Full network outage — dns + network + gateway all failing
      {
        id: 'full-network-outage',
        description: 'Complete network failure: DNS, connectivity, and gateway all unreachable',
        cooldownMs: 10 * 60 * 1000,
        conditions: (signals) => {
          const hasNetwork = signals.some(ws =>
            ws.signal.category === 'network' && (ws.signal.metric === 'connectivity' || ws.signal.id?.includes('network-down'))
          );
          const hasDns = signals.some(ws =>
            ws.signal.id?.includes('dns-failure') || (ws.signal.category === 'network' && ws.signal.metric === 'dns')
          );
          const hasGateway = signals.some(ws =>
            ws.signal.id?.includes('gateway') || (ws.signal.category === 'network' && ws.signal.metric === 'gateway')
          );

          // Need at least 2 of 3 network-related failures
          const networkSignals = [hasNetwork, hasDns, hasGateway].filter(Boolean).length;
          if (networkSignals >= 2) {
            const matched = signals
              .filter(ws => ws.signal.category === 'network')
              .map(ws => ws.signal.id);
            return matched.length > 0 ? matched : null;
          }
          return null;
        },
        action: {
          type: 'boost_confidence',
          confidenceBoost: 95,
          suggestedPlaybook: 'full-network-reset'
        }
      }
    ];
  }
}
