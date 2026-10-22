#!/usr/bin/env node
/**
 * patchnow SessionStart hook.
 *
 * Runs when a Claude Code session starts in a project. Scans the project for
 * vulnerabilities that are getting traction and, only if something is P0/P1,
 * prints a short alert that Claude sees as context. Prints nothing otherwise.
 *
 * Read-only: it never modifies the project. Results are cached per project for
 * six hours, keyed on the manifest files' paths and mtimes, so repeat session
 * starts cost milliseconds and never hit the network.
 *
 * Disable with PATCHNOW_DISABLE=1.
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { scanProject, renderHook, findManifests, log } from '../skills/patchnow/scripts/scan.mjs';

const SCAN_SCRIPT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'skills', 'patchnow', 'scripts', 'scan.mjs');
const CACHE_DIR = process.env.PATCHNOW_CACHE_DIR || path.join(os.homedir(), '.cache', 'patchnow');
const PROJECT_TTL_MS = 6 * 3600 * 1000;
const DEADLINE_MS = 25_000;

function readStdin() {
  return new Promise((resolve) => {
    let data = '';
    const done = () => resolve(data);
    if (process.stdin.isTTY) return resolve('');
    const timer = setTimeout(done, 300);
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => { data += c; });
    process.stdin.on('end', () => { clearTimeout(timer); done(); });
    process.stdin.on('error', () => { clearTimeout(timer); done(); });
  });
}

function logLine(msg) {
  try { fs.mkdirSync(CACHE_DIR, { recursive: true }); fs.appendFileSync(path.join(CACHE_DIR, 'hook.log'), `${new Date().toISOString()} ${msg}\n`); } catch { /* ignore */ }
}

function inventoryHash(root, files) {
  const h = crypto.createHash('sha1');
  for (const f of files) {
    try { const st = fs.statSync(path.join(root, f)); h.update(`${f}:${st.size}:${Math.floor(st.mtimeMs)}\n`); } catch { h.update(`${f}:gone\n`); }
  }
  return h.digest('hex');
}

async function main() {
  if (process.env.PATCHNOW_DISABLE === '1') return;
  let input = {};
  try { input = JSON.parse(await readStdin() || '{}'); } catch { /* not JSON, fine */ }
  const root = path.resolve(input.cwd || process.env.CLAUDE_PROJECT_DIR || process.cwd());

  const files = findManifests(root);
  if (!files.length) return; // not a project we can help with

  const hash = inventoryHash(root, files);
  const cacheFile = path.join(CACHE_DIR, 'projects', crypto.createHash('sha1').update(root).digest('hex') + '.json');
  try {
    const c = JSON.parse(fs.readFileSync(cacheFile, 'utf8'));
    if (c.hash === hash && Date.now() - c.ts < PROJECT_TTL_MS) { if (c.text) process.stdout.write(c.text + '\n'); return; }
  } catch { /* no cache */ }

  log.quiet = true;
  const opts = { quiet: true, offline: false, noCache: false, cacheTtl: 6 * 3600, timeout: 8000, local: true, min: 'P3' };
  const report = await Promise.race([
    scanProject(root, opts),
    new Promise((_, reject) => setTimeout(() => reject(new Error(`scan exceeded ${DEADLINE_MS}ms`)), DEADLINE_MS)),
  ]);
  const text = renderHook(report, SCAN_SCRIPT);
  try { fs.mkdirSync(path.dirname(cacheFile), { recursive: true }); fs.writeFileSync(cacheFile, JSON.stringify({ hash, ts: Date.now(), text, root })); } catch { /* ignore */ }
  if (text) process.stdout.write(text + '\n');
}

main().catch((e) => { logLine(`hook error: ${e?.stack || e}`); }).finally(() => process.exit(0));
