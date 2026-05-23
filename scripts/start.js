#!/usr/bin/env node
/**
 * SACA v14 — Start all services (cross-platform: Windows / Linux / macOS).
 *
 * Usage:  node scripts/start.js        (starts all 3 services)
 *         node scripts/start.js core    (Python Core only)
 *         node scripts/start.js api     (Express API only)
 *         node scripts/start.js web     (Vite frontend only)
 */

const { spawn, execSync } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');

const ROOT = path.resolve(__dirname, '..');
const IS_WIN = os.platform() === 'win32';

// ─── Resolve paths ──────────────────────────────────────────────────────────

const VENV_PYTHON = IS_WIN
  ? path.join(ROOT, '.venv', 'Scripts', 'python.exe')
  : path.join(ROOT, '.venv', 'bin', 'python');

function resolvePython() {
  if (fs.existsSync(VENV_PYTHON)) return VENV_PYTHON;
  // fallback: system python
  return IS_WIN ? 'python' : 'python3';
}

const PYTHON = resolvePython();

// ─── Helpers ────────────────────────────────────────────────────────────────

function startService(name, label, cwd, cmd, args = []) {
  console.log(`[start] ${label} → ${cwd}`);
  const child = spawn(cmd, args, {
    cwd,
    stdio: 'inherit',
    shell: IS_WIN,
  });
  child.on('error', (err) => {
    console.error(`[${label}] Failed to start: ${err.message}`);
  });
  child.on('exit', (code) => {
    if (code !== 0 && code !== null) {
      console.error(`[${label}] Exited with code ${code}`);
    }
  });
  return child;
}

// ─── Services ───────────────────────────────────────────────────────────────

const services = {
  core: {
    label: 'CORE',
    cwd: path.join(ROOT, 'apps', 'core-py'),
    cmd: PYTHON,
    args: ['main.py'],
  },
  api: {
    label: 'API',
    cwd: path.join(ROOT, 'apps', 'api-ts'),
    cmd: 'npx',
    args: ['tsx', 'src/index.ts'],
  },
  web: {
    label: 'WEB',
    cwd: path.join(ROOT, 'apps', 'web'),
    cmd: 'npx',
    args: ['vite', '--port', '5173'],
  },
};

// ─── Main ───────────────────────────────────────────────────────────────────

const target = process.argv[2];

if (target && !services[target]) {
  console.error(`Unknown service: ${target}. Use: core | api | web`);
  process.exit(1);
}

if (target) {
  const svc = services[target];
  startService(target, svc.label, svc.cwd, svc.cmd, svc.args);
} else {
  console.log('═'.repeat(44));
  console.log('  SACA v14 — Starting all services');
  console.log('═'.repeat(44));
  console.log(`  Python:  ${PYTHON}`);
  console.log(`  OS:      ${os.platform()}`);
  console.log('═'.repeat(44));
  console.log('');

  // Start Python Core first, then API + Web after a short delay
  const coreProc = startService('core', 'CORE', services.core.cwd, services.core.cmd, services.core.args);

  setTimeout(() => {
    startService('api', 'API', services.api.cwd, services.api.cmd, services.api.args);
    setTimeout(() => {
      startService('web', 'WEB', services.web.cwd, services.web.cmd, services.web.args);
      console.log('');
      console.log('  Python Core : http://localhost:8000');
      console.log('  Express API : http://localhost:3001');
      console.log('  Frontend    : http://localhost:5173');
      console.log('');
      console.log('  Run "node scripts/stop.js" to stop all servers.');
    }, 2000);
  }, 4000);
}
