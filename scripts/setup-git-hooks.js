#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const repoRoot = process.cwd();
const gitDir = path.join(repoRoot, '.git');
if (!fs.existsSync(gitDir) || !fs.statSync(gitDir).isDirectory()) {
  console.log('[hooks] .git directory not found. Initialize git first, then run this script again.');
  process.exit(0);
}

const hooksDir = path.join(gitDir, 'hooks');
if (!fs.existsSync(hooksDir)) {
  fs.mkdirSync(hooksDir, { recursive: true });
}

const hookPath = path.join(hooksDir, 'pre-commit');
const hookContent = `#!/bin/sh
node scripts/secret-scan-staged.js
status=$?
if [ $status -ne 0 ]; then
  echo "[pre-commit] Blocked commit due to possible secrets."
  exit $status
fi
exit 0
`;

fs.writeFileSync(hookPath, hookContent, 'utf8');
try {
  fs.chmodSync(hookPath, 0o755);
} catch (_e) {
  // On Windows, chmod may be a no-op.
}

console.log('[hooks] Installed .git/hooks/pre-commit');
