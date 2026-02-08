import { isVerificationStep } from '../src/service/agent-service';

// Minimal PlaybookStep shape matching the interface
function step(type: string, action: string, opts: Record<string, any> = {}): any {
  return { type, action, params: {}, ...opts };
}

describe('isVerificationStep', () => {
  // ── Process kill → Get-Process verification ──────────────────────

  it('detects Get-Process after Stop-Process as verification', () => {
    const steps = [
      step('powershell', 'Stop-Process -Id 15464 -Force'),
      step('powershell', 'Get-Process -Name SystemSettings -ErrorAction SilentlyContinue'),
    ];
    expect(isVerificationStep(steps[1], steps, 1)).toBe(true);
  });

  it('detects Get-Process after taskkill as verification', () => {
    const steps = [
      step('powershell', 'taskkill /PID 1234 /F'),
      step('powershell', 'Get-Process -Name notepad'),
    ];
    expect(isVerificationStep(steps[1], steps, 1)).toBe(true);
  });

  it('detects Get-Process after a kill command as verification', () => {
    const steps = [
      step('powershell', 'kill -Name chrome'),
      step('powershell', 'Get-Process -Name chrome'),
    ];
    expect(isVerificationStep(steps[1], steps, 1)).toBe(true);
  });

  it('detects Get-Process verification even with intermediate steps', () => {
    const steps = [
      step('powershell', 'Stop-Process -Id 999 -Force'),
      step('powershell', 'Start-Sleep -Seconds 3'),
      step('powershell', 'Get-Process -Name myapp'),
    ];
    // index 2, should look back and find Stop-Process at index 0
    expect(isVerificationStep(steps[2], steps, 2)).toBe(true);
  });

  // ── Service actions → Get-Service verification ───────────────────

  it('detects Get-Service after Restart-Service as verification', () => {
    const steps = [
      step('powershell', 'Restart-Service -Name W32Time -Force'),
      step('powershell', 'Get-Service -Name W32Time'),
    ];
    expect(isVerificationStep(steps[1], steps, 1)).toBe(true);
  });

  it('detects Get-Service after Start-Service as verification', () => {
    const steps = [
      step('powershell', 'Start-Service -Name Spooler'),
      step('powershell', 'Get-Service -Name Spooler'),
    ];
    expect(isVerificationStep(steps[1], steps, 1)).toBe(true);
  });

  it('detects Get-Service after Stop-Service as verification', () => {
    const steps = [
      step('powershell', 'Stop-Service -Name Spooler -Force'),
      step('powershell', 'Get-Service -Name Spooler'),
    ];
    expect(isVerificationStep(steps[1], steps, 1)).toBe(true);
  });

  it('detects Get-Service after net start as verification', () => {
    const steps = [
      step('powershell', 'net start W32Time'),
      step('powershell', 'Get-Service W32Time'),
    ];
    expect(isVerificationStep(steps[1], steps, 1)).toBe(true);
  });

  it('detects Get-Service after net stop as verification', () => {
    const steps = [
      step('powershell', 'net stop Spooler'),
      step('powershell', 'Get-Service Spooler'),
    ];
    expect(isVerificationStep(steps[1], steps, 1)).toBe(true);
  });

  // ── Negative cases (should NOT be detected as verification) ──────

  it('does not flag Get-Process as first step', () => {
    const steps = [
      step('powershell', 'Get-Process -Id 15464 | Select-Object Name, Id'),
    ];
    expect(isVerificationStep(steps[0], steps, 0)).toBe(false);
  });

  it('does not flag Get-Process without a preceding kill step', () => {
    const steps = [
      step('powershell', 'Start-Sleep -Seconds 5'),
      step('powershell', 'Get-Process -Name explorer'),
    ];
    expect(isVerificationStep(steps[1], steps, 1)).toBe(false);
  });

  it('does not flag Get-Service without a preceding service action', () => {
    const steps = [
      step('powershell', 'Write-Host "checking"'),
      step('powershell', 'Get-Service -Name W32Time'),
    ];
    expect(isVerificationStep(steps[1], steps, 1)).toBe(false);
  });

  it('does not flag non-powershell steps', () => {
    const steps = [
      step('service', 'stop', { params: { serviceName: 'W32Time' } }),
      step('service', 'Get-Service W32Time'),
    ];
    expect(isVerificationStep(steps[1], steps, 1)).toBe(false);
  });

  it('does not flag a Stop-Process step itself', () => {
    const steps = [
      step('powershell', 'Get-Process -Id 123 | Select-Object Name'),
      step('powershell', 'Stop-Process -Id 123 -Force'),
    ];
    expect(isVerificationStep(steps[1], steps, 1)).toBe(false);
  });

  // ── allowFailure flag ────────────────────────────────────────────

  it('allowFailure flag is respected independently of heuristic', () => {
    const s = step('powershell', 'Some-Random-Command', { allowFailure: true });
    // allowFailure is checked in executePlaybook, not in isVerificationStep
    // isVerificationStep only does heuristic detection
    expect(isVerificationStep(s, [s], 0)).toBe(false);
  });

  // ── Real-world scenario from logs ────────────────────────────────

  it('matches the exact SystemSettings scenario from agent logs', () => {
    const steps = [
      step('powershell', 'Get-Process -Id 15464 -ErrorAction SilentlyContinue | Select-Object Name, Id, Responding, StartTime'),
      step('powershell', 'Stop-Process -Id 15464 -Force -ErrorAction SilentlyContinue'),
      step('powershell', 'Start-Sleep -Seconds 3; Get-Process -Name SystemSettings -ErrorAction SilentlyContinue'),
    ];
    // Step 0: diagnostic (no prior kill) → not verification
    expect(isVerificationStep(steps[0], steps, 0)).toBe(false);
    // Step 1: the kill itself → not verification
    expect(isVerificationStep(steps[1], steps, 1)).toBe(false);
    // Step 2: Get-Process after Stop-Process → verification
    expect(isVerificationStep(steps[2], steps, 2)).toBe(true);
  });

  it('matches the Claude memory usage scenario from agent logs', () => {
    const steps = [
      step('powershell', 'Get-Process -Id 6552 -ErrorAction SilentlyContinue | Select-Object Name, Id, WorkingSet, Handles, Threads, StartTime | Format-List'),
      step('powershell', 'Stop-Process -Id 6552 -Force -ErrorAction SilentlyContinue'),
      step('powershell', "Start-Sleep -Seconds 3; Get-Process -Name 'claude' -ErrorAction SilentlyContinue | Select-Object Name, Id, WorkingSet"),
    ];
    expect(isVerificationStep(steps[2], steps, 2)).toBe(true);
  });
});
