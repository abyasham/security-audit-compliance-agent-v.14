#!/usr/bin/env node
/**
 * SACA v14 — Stop all services (cross-platform: Windows / Linux / macOS).
 *
 * Kills processes on ports 8000, 3001, 5173.
 * Usage:  node scripts/stop.js
 */

const { execSync } = require('child_process');
const os = require('os');

const IS_WIN = os.platform() === 'win32';
const PORTS = [8000, 3001, 5173];

// ─── Helpers ────────────────────────────────────────────────────────────────

function killPortWindows(port) {
  try {
    const out = execSync(`netstat -ano | findstr :${port}`, { encoding: 'utf-8', windowsHide: true });
    const lines = out.trim().split('\n');
    const killed = new Set();
    for (const line of lines) {
      const parts = line.trim().split(/\s+/);
      const pid = parts[parts.length - 1];
      if (pid && !isNaN(parseInt(pid)) && !killed.has(pid)) {
        killed.add(pid);
        try {
          execSync(`taskkill /F /PID ${pid}`, { windowsHide: true });
          console.log(`[stop] Port ${port} → killed PID ${pid}`);
        } catch { /* already dead */ }
      }
    }
  } catch { /* no process on port */ }
}

function killPortUnix(port) {
  try {
    // lsof -ti :PORT → list PIDs, then kill them
    const out = execSync(`lsof -ti :${port}`, { encoding: 'utf-8' });
    const pids = out.trim().split('\n').filter(Boolean);
    const killed = new Set();
    for (const pid of pids) {
      if (!killed.has(pid)) {
        killed.add(pid);
        try {
          execSync(`kill -9 ${pid}`);
          console.log(`[stop] Port ${port} → killed PID ${pid}`);
        } catch { /* already dead */ }
      }
    }
  } catch { /* no process on port */ }
}

// ─── Main ───────────────────────────────────────────────────────────────────

console.log('═'.repeat(44));
console.log('  SACA v14 — Stopping all services');
console.log('═'.repeat(44));

for (const port of PORTS) {
  if (IS_WIN) {
    killPortWindows(port);
  } else {
    killPortUnix(port);
  }
}

// Also kill any orphaned Python/uvicorn processes for this project
try {
  if (IS_WIN) {
    // Use WMIC to find python processes with main.py or uvicorn in their command line
    const out = execSync(
      'wmic process where "name=\'python.exe\' or name=\'python3.exe\'" get ProcessId,CommandLine /format:csv 2>nul',
      { encoding: 'utf-8', windowsHide: true }
    );
    for (const line of out.split('\n')) {
      if ((line.includes('main.py') || line.includes('uvicorn')) && !line.includes('wmic')) {
        const pid = line.trim().split(',').pop()?.trim();
        if (pid && /^\d+$/.test(pid) && pid !== '0') {
          try {
            execSync(`taskkill /F /PID ${pid} 2>nul`, { windowsHide: true });
            console.log(`[stop] Python/uvicorn → killed PID ${pid}`);
          } catch { /* already dead */ }
        }
      }
    }
  } else {
    execSync("pkill -f 'python.*main.py' 2>/dev/null || true", { encoding: 'utf-8' });
    execSync("pkill -f 'uvicorn main:app' 2>/dev/null || true", { encoding: 'utf-8' });
  }
} catch { /* ignore */ }

console.log('[stop] All SACA servers stopped.');
