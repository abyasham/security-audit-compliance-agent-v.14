#!/usr/bin/env node
const { spawnSync } = require('child_process');
const fs = require('fs');

function runGit(args) {
  const res = spawnSync('git', args, { encoding: 'utf8' });
  if (res.error) {
    throw res.error;
  }
  if (res.status !== 0) {
    throw new Error((res.stderr || res.stdout || 'git command failed').trim());
  }
  return res.stdout;
}

function hasMatch(text, patterns) {
  return patterns.some((re) => re.test(text));
}

try {
  if (!fs.existsSync('.git')) {
    console.log('[secret-scan] .git directory not found. Initialize git first.');
    process.exit(0);
  }

  const stagedFilesRaw = runGit(['diff', '--cached', '--name-only', '--diff-filter=ACMR']);
  const stagedFiles = stagedFilesRaw
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);

  if (stagedFiles.length === 0) {
    process.exit(0);
  }

  const blockedNamePatterns = [
    /(^|\/)\.env($|\.)/i,
    /(^|\/)\.env\.local$/i,
    /(^|\/)\.env\.docker$/i,
    /(^|\/)secrets?\//i,
    /(^|\/)credentials?\//i,
    /\.pem$/i,
    /\.p12$/i,
    /\.pfx$/i,
    /id_rsa$/i,
    /id_ed25519$/i,
  ];

  const blockedByName = stagedFiles.filter((f) => hasMatch(f, blockedNamePatterns));
  if (blockedByName.length > 0) {
    console.error('[secret-scan] Blocked staged files by filename policy:');
    for (const f of blockedByName) console.error(` - ${f}`);
    process.exit(1);
  }

  const stagedPatch = runGit(['diff', '--cached', '--unified=0']);
  const secretValuePatterns = [
    /sk-[A-Za-z0-9_-]{16,}/,
    /sk-proj-[A-Za-z0-9_-]{16,}/,
    /sk-or-v1-[A-Za-z0-9_-]{16,}/,
    /Bearer\s+[A-Za-z0-9._-]{16,}/i,
    /(OPENAI_API_KEY|DEEPSEEK_API_KEY|OPENROUTER_API_KEY)\s*=\s*[^\s#]{8,}/,
  ];

  if (hasMatch(stagedPatch, secretValuePatterns)) {
    console.error('[secret-scan] Possible secret detected in staged diff. Remove it before commit.');
    process.exit(1);
  }

  process.exit(0);
} catch (err) {
  console.error(`[secret-scan] ${err.message}`);
  process.exit(1);
}
