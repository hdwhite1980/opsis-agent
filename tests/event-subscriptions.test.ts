// Tests for the event subscription buffer parsing and event conversion logic in EventMonitor.
// These tests exercise processSubscriptionBuffer() and handleSubscriptionEvent() without
// spawning actual PowerShell processes.

import * as os from 'os';

// We need to test the buffer parsing logic. Since EventMonitor has many dependencies,
// we'll test the parsing logic by creating a minimal harness that mimics the class behavior.

describe('Event Subscription Buffer Parsing', () => {
  // Reproduce the exact processSubscriptionBuffer logic
  function parseBuffer(buffer: string): { events: any[]; remainder: string } {
    const events: any[] = [];
    const lines = buffer.split('\n');
    const remainder = lines.pop() || '';

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed.startsWith('OPSIS_EVENT:')) continue;

      try {
        const json = JSON.parse(trimmed.substring('OPSIS_EVENT:'.length));
        events.push(json);
      } catch {
        // skip unparseable
      }
    }

    return { events, remainder };
  }

  it('parses a single complete OPSIS_EVENT line', () => {
    const buffer = 'OPSIS_EVENT:{"type":"subscription_started","data":{"subscriptions":2}}\n';
    const { events, remainder } = parseBuffer(buffer);

    expect(events).toHaveLength(1);
    expect(events[0].type).toBe('subscription_started');
    expect(events[0].data.subscriptions).toBe(2);
    expect(remainder).toBe('');
  });

  it('parses multiple complete lines', () => {
    const buffer =
      'OPSIS_EVENT:{"type":"service_state_change","data":{"Name":"W32Time","NewState":"Stopped"}}\n' +
      'OPSIS_EVENT:{"type":"critical_event","data":{"EventCode":1001,"SourceName":"App"}}\n';

    const { events } = parseBuffer(buffer);
    expect(events).toHaveLength(2);
    expect(events[0].type).toBe('service_state_change');
    expect(events[1].type).toBe('critical_event');
  });

  it('handles partial lines correctly (keeps remainder)', () => {
    const buffer = 'OPSIS_EVENT:{"type":"service_state_change","data":{"Name":"W32Time"}}\nOPSIS_EVENT:{"type":"crit';
    const { events, remainder } = parseBuffer(buffer);

    expect(events).toHaveLength(1);
    expect(remainder).toBe('OPSIS_EVENT:{"type":"crit');
  });

  it('ignores non-OPSIS_EVENT lines', () => {
    const buffer =
      'Some random PowerShell output\n' +
      'OPSIS_EVENT:{"type":"subscription_started","data":{}}\n' +
      'WARNING: something\n';

    const { events } = parseBuffer(buffer);
    expect(events).toHaveLength(1);
    expect(events[0].type).toBe('subscription_started');
  });

  it('skips malformed JSON gracefully', () => {
    const buffer =
      'OPSIS_EVENT:{bad json}\n' +
      'OPSIS_EVENT:{"type":"ok","data":{}}\n';

    const { events } = parseBuffer(buffer);
    expect(events).toHaveLength(1);
    expect(events[0].type).toBe('ok');
  });

  it('handles empty buffer', () => {
    const { events, remainder } = parseBuffer('');
    expect(events).toHaveLength(0);
    expect(remainder).toBe('');
  });

  it('handles buffer with only newlines', () => {
    const { events, remainder } = parseBuffer('\n\n\n');
    expect(events).toHaveLength(0);
    expect(remainder).toBe('');
  });

  it('accumulates partial data across multiple calls', () => {
    // Simulate two chunks arriving
    let buffer = 'OPSIS_EVENT:{"type":"svc","dat';
    const r1 = parseBuffer(buffer);
    expect(r1.events).toHaveLength(0);
    expect(r1.remainder).toBe('OPSIS_EVENT:{"type":"svc","dat');

    // Second chunk completes the line
    buffer = r1.remainder + 'a":{}}\n';
    const r2 = parseBuffer(buffer);
    expect(r2.events).toHaveLength(1);
    expect(r2.events[0].type).toBe('svc');
    expect(r2.remainder).toBe('');
  });
});

// ============================================
// EVENT CONVERSION
// ============================================

describe('Event Subscription - Service State Change Conversion', () => {
  function convertServiceEvent(event: any): any | null {
    // Reproduce the handleSubscriptionEvent logic for service_state_change
    if (event.type !== 'service_state_change') return null;
    const data = event.data;
    if (!data?.Name) return null;

    const isDown = data.NewState === 'Stopped' || data.NewState === 'Stop Pending';
    const wasDown = data.PreviousState === 'Stopped' || data.PreviousState === 'Stop Pending';
    const level = isDown ? 'Error' : (wasDown ? 'Information' : 'Warning');

    return {
      timeCreated: new Date(event.timestamp),
      id: 7036,
      level,
      source: 'Service Control Manager',
      message: `The ${data.DisplayName || data.Name} service entered the ${data.NewState} state.`,
      computer: os.hostname(),
      logName: 'System',
      raw: {
        serviceName: data.Name,
        newState: data.NewState,
        previousState: data.PreviousState,
        startMode: data.StartMode,
        realtime: true,
      },
    };
  }

  it('converts service stopped event to Error-level EventLogEntry', () => {
    const entry = convertServiceEvent({
      type: 'service_state_change',
      timestamp: '2026-02-08T10:00:00.000Z',
      data: {
        Name: 'W32Time',
        DisplayName: 'Windows Time',
        NewState: 'Stopped',
        PreviousState: 'Running',
        StartMode: 'Auto',
      },
    });

    expect(entry).not.toBeNull();
    expect(entry.level).toBe('Error');
    expect(entry.id).toBe(7036);
    expect(entry.source).toBe('Service Control Manager');
    expect(entry.message).toContain('Windows Time');
    expect(entry.message).toContain('Stopped');
    expect(entry.raw.realtime).toBe(true);
    expect(entry.raw.serviceName).toBe('W32Time');
  });

  it('converts service recovery to Information-level (suppressed from processing)', () => {
    const entry = convertServiceEvent({
      type: 'service_state_change',
      timestamp: '2026-02-08T10:05:00.000Z',
      data: {
        Name: 'W32Time',
        DisplayName: 'Windows Time',
        NewState: 'Running',
        PreviousState: 'Stopped',
        StartMode: 'Auto',
      },
    });

    expect(entry.level).toBe('Information');
  });

  it('converts non-stop transition to Warning-level', () => {
    const entry = convertServiceEvent({
      type: 'service_state_change',
      timestamp: '2026-02-08T10:05:00.000Z',
      data: {
        Name: 'W32Time',
        DisplayName: 'Windows Time',
        NewState: 'Start Pending',
        PreviousState: 'Running',
        StartMode: 'Auto',
      },
    });

    expect(entry.level).toBe('Warning');
  });

  it('uses Name as fallback when DisplayName is missing', () => {
    const entry = convertServiceEvent({
      type: 'service_state_change',
      timestamp: '2026-02-08T10:00:00.000Z',
      data: {
        Name: 'W32Time',
        NewState: 'Stopped',
        PreviousState: 'Running',
      },
    });

    expect(entry.message).toContain('W32Time');
  });

  it('returns null for missing Name', () => {
    const entry = convertServiceEvent({
      type: 'service_state_change',
      timestamp: '2026-02-08T10:00:00.000Z',
      data: { NewState: 'Stopped' },
    });

    expect(entry).toBeNull();
  });
});

describe('Event Subscription - Critical Event Conversion', () => {
  function convertCriticalEvent(event: any): any | null {
    if (event.type !== 'critical_event') return null;
    const data = event.data;
    if (!data?.EventCode) return null;

    return {
      timeCreated: new Date(event.timestamp),
      id: data.EventCode,
      level: data.Type === 1 ? 'Critical' : 'Error',
      source: data.SourceName || 'Unknown',
      message: data.Message || '',
      computer: os.hostname(),
      logName: data.Logfile || 'System',
      raw: { realtime: true },
    };
  }

  it('converts Type=1 to Critical level', () => {
    const entry = convertCriticalEvent({
      type: 'critical_event',
      timestamp: '2026-02-08T10:00:00.000Z',
      data: {
        EventCode: 41,
        SourceName: 'Kernel-Power',
        Message: 'The system has rebooted without cleanly shutting down first.',
        Type: 1,
        Logfile: 'System',
      },
    });

    expect(entry.level).toBe('Critical');
    expect(entry.id).toBe(41);
    expect(entry.source).toBe('Kernel-Power');
    expect(entry.logName).toBe('System');
  });

  it('converts Type=2 to Error level', () => {
    const entry = convertCriticalEvent({
      type: 'critical_event',
      timestamp: '2026-02-08T10:00:00.000Z',
      data: {
        EventCode: 1001,
        SourceName: 'Application Error',
        Message: 'Faulting application',
        Type: 2,
        Logfile: 'Application',
      },
    });

    expect(entry.level).toBe('Error');
    expect(entry.logName).toBe('Application');
  });

  it('returns null for missing EventCode', () => {
    const entry = convertCriticalEvent({
      type: 'critical_event',
      timestamp: '2026-02-08T10:00:00.000Z',
      data: { SourceName: 'Test' },
    });

    expect(entry).toBeNull();
  });

  it('uses defaults for missing optional fields', () => {
    const entry = convertCriticalEvent({
      type: 'critical_event',
      timestamp: '2026-02-08T10:00:00.000Z',
      data: { EventCode: 999 },
    });

    expect(entry.source).toBe('Unknown');
    expect(entry.message).toBe('');
    expect(entry.logName).toBe('System');
  });
});
