#!/usr/bin/env node
/**
 * SACA v14 — Full reset (stop, clear data, restart).
 * Cross-platform: Windows / Linux / macOS.
 *
 * Usage:  node scripts/reset.js
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const UPLOADS_DIR = path.join(ROOT, 'apps', 'api-ts', 'uploads');
const DATA_DIR = path.join(ROOT, 'apps', 'api-ts', 'data');

// ─── Step 1: Stop servers ───────────────────────────────────────────────

console.log('[reset] Step 1/3 — Stopping servers...');
try {
  execSync(`node "${path.join(__dirname, 'stop.js')}"`, { stdio: 'inherit', cwd: ROOT });
} catch { /* ignore exit code */ }

// ─── Step 2: Clear data ─────────────────────────────────────────────────

console.log('[reset] Step 2/3 — Clearing uploads + session data...');

function clearDir(dir, label) {
  if (fs.existsSync(dir)) {
    const files = fs.readdirSync(dir);
    for (const f of files) {
      const fp = path.join(dir, f);
      try {
        fs.rmSync(fp, { recursive: true });
      } catch { /* locked / busy */ }
    }
    console.log(`[reset]   ${label}: ${files.length} items removed`);
  } else {
    fs.mkdirSync(dir, { recursive: true });
  }
}

clearDir(UPLOADS_DIR, 'uploads');
clearDir(DATA_DIR, 'data');

// ─── Step 3: Restart ─────────────────────────────────────────────────────

console.log('[reset] Step 3/3 — Restarting servers...');
setTimeout(() => {
  execSync(`node "${path.join(__dirname, 'start.js')}"`, { stdio: 'inherit', cwd: ROOT });
}, 1000);
