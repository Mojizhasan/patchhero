#!/usr/bin/env node
/**
 * patchhero — scan a project for vulnerabilities that are getting traction and
 * tell you exactly what to patch first.
 *
 * Zero dependencies. Node 18+. Reads lockfiles, manifests, Dockerfiles and
 * version files, then asks free public feeds:
 *
 *   OSV.dev            which package versions are vulnerable (npm, Packagist, PyPI, Go, crates.io, RubyGems, NuGet, Maven)
 *   NVD                CVEs against runtimes (PHP, Node, Python, Ruby, Go, nginx, WordPress) by CPE
 *   endoflife.date     latest patch release per runtime line, and whether a line is EOL
 *   CISA KEV           vulnerabilities confirmed exploited in the wild
 *   FIRST EPSS         probability a CVE is exploited in the next 30 days
 *
 * Priority (the "traction" score) is explained in references/priority.md.
 *
 *   node scan.mjs [dir] [--json|--md|--hook] [--fail-on P0] [--local] [--all] [--offline]
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const SELF = fileURLToPath(import.meta.url);

export const VERSION = '0.1.0';
const UA = `patchhero/${VERSION} (+https://github.com/Mojizhasan/patchhero)`;
const DAY = 86_400_000;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const opts = {
    dirs: [], json: false, md: false, hook: false, quiet: false, offline: false,
    noCache: false, cacheTtl: 6 * 3600, failOn: 'none', min: 'P3', local: false,
    all: false, timeout: 15_000, help: false, version: false, color: process.stdout.isTTY,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => argv[++i];
    switch (a) {
      case '--json': opts.json = true; break;
      case '--md': opts.md = true; break;
      case '--hook': opts.hook = true; opts.quiet = true; break;
      case '--quiet': case '-q': opts.quiet = true; break;
      case '--offline': opts.offline = true; break;
      case '--no-cache': opts.noCache = true; break;
      case '--no-color': opts.color = false; break;
      case '--cache-ttl': opts.cacheTtl = Number(next()); break;
      case '--fail-on': opts.failOn = String(next()).toUpperCase(); break;
      case '--min': opts.min = String(next()).toUpperCase(); break;
      case '--local': opts.local = true; break;
      case '--all': opts.all = true; break;
      case '--timeout': opts.timeout = Number(next()); break;
      case '--help': case '-h': opts.help = true; break;
      case '--version': case '-v': opts.version = true; break;
      default:
        if (a.startsWith('-')) throw new Error(`Unknown flag: ${a}`);
        opts.dirs.push(a);
    }
  }
  if (opts.dirs.length === 0) opts.dirs.push(process.cwd());
  return opts;
}

const HELP = `patchhero ${VERSION} — find the vulnerabilities that matter today and how to patch them

Usage: node scan.mjs [dir ...] [options]

Options:
  --json            machine-readable report
  --md              GitHub-issue-ready markdown
  --hook            compact Claude Code SessionStart alert (prints nothing when clean)
  --fail-on P0|P1|P2|P3   exit 2 when a finding at/above this level exists (CI gate)
  --min P0..P3      only show findings at/above this level (default P3 = all)
  --local           also check runtimes installed on this machine (php -v, node -v, ...)
  --all             treat <dir> as a folder of projects and scan each one
  --offline         use cached feed data only
  --no-cache        ignore cached feed data
  --cache-ttl SEC   feed cache lifetime (default 21600 = 6h)
  --timeout MS      per-request network timeout (default 15000)
  --quiet           no progress on stderr
  -h, --help        this help

Exit codes: 0 ok · 2 findings at/above --fail-on · 1 error
`;

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

export const log = { quiet: false, msg(s) { if (!this.quiet) process.stderr.write(`patchhero: ${s}\n`); } };

export function cmpVersions(a, b) {
  // Lenient comparison across ecosystems. Numeric segments compare numerically,
  // pre-release tags sort before the release they qualify.
  const norm = (v) => String(v).trim().replace(/^v/i, '');
  const split = (v) => norm(v).split(/[.\-+_~]/).filter(Boolean).flatMap((seg) => {
    const m = seg.match(/^(\d+)([a-zA-Z]+)(\d*)$/); // 1rc2 -> 1, rc, 2
    return m ? [m[1], m[2], m[3]].filter(Boolean) : [seg];
  });
  const A = split(a), B = split(b);
  const n = Math.max(A.length, B.length);
  for (let i = 0; i < n; i++) {
    const x = A[i], y = B[i];
    if (x === undefined) return /^[a-zA-Z]/.test(y) ? 1 : -1; // 1.0 > 1.0-rc ; 1.0 < 1.0.1
    if (y === undefined) return /^[a-zA-Z]/.test(x) ? -1 : 1;
    const xn = /^\d+$/.test(x), yn = /^\d+$/.test(y);
    if (xn && yn) { const d = Number(x) - Number(y); if (d) return d < 0 ? -1 : 1; continue; }
    if (xn !== yn) return xn ? 1 : -1; // numbers beat words (1.0.1 > 1.0.rc)
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

function daysAgo(iso) { if (!iso) return null; const t = Date.parse(iso); return Number.isNaN(t) ? null : Math.floor((Date.now() - t) / DAY); }
function sha1(s) { return crypto.createHash('sha1').update(s).digest('hex'); }
function readText(p) { try { return fs.readFileSync(p, 'utf8'); } catch { return null; } }
function readJson(p) { const t = readText(p); if (t == null) return null; try { return JSON.parse(t.replace(/^﻿/, '')); } catch { return null; } }
function uniqBy(arr, key) { const seen = new Set(); return arr.filter((x) => { const k = key(x); if (seen.has(k)) return false; seen.add(k); return true; }); }

async function pMap(items, fn, concurrency = 6) {
  const out = new Array(items.length); let i = 0;
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (i < items.length) { const idx = i++; out[idx] = await fn(items[idx], idx); }
  });
  await Promise.all(workers);
  return out;
}

// ---------------------------------------------------------------------------
// Cache (feed data only — never project data)
// ---------------------------------------------------------------------------

const CACHE_DIR = process.env.PATCHHERO_CACHE_DIR || path.join(os.homedir(), '.cache', 'patchhero');
function cachePath(name) { return path.join(CACHE_DIR, name); }
function cacheGet(name, ttlSec) {
  try {
    const p = cachePath(name); const st = fs.statSync(p);
    if (ttlSec != null && Date.now() - st.mtimeMs > ttlSec * 1000) return null;
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch { return null; }
}
function cacheSet(name, data) {
  try { fs.mkdirSync(path.dirname(cachePath(name)), { recursive: true }); fs.writeFileSync(cachePath(name), JSON.stringify(data)); } catch { /* cache is best-effort */ }
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

async function http(url, { method = 'GET', body, timeout = 15_000, headers = {} } = {}) {
  const res = await fetch(url, {
    method, body: body ? JSON.stringify(body) : undefined,
    headers: { 'User-Agent': UA, Accept: 'application/json', ...(body ? { 'Content-Type': 'application/json' } : {}), ...headers },
    signal: AbortSignal.timeout(timeout),
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText} for ${url}`);
  return res.json();
}

// ---------------------------------------------------------------------------
// Inventory: what does this project run?
// ---------------------------------------------------------------------------

const SKIP_DIRS = new Set(['node_modules', 'vendor', '.git', 'dist', 'build', '.next', '.nuxt', 'out', 'target', '__pycache__',
  '.venv', 'venv', 'env', '.tox', '.cache', 'coverage', '.idea', '.vscode', 'bower_components', '.terraform', '.svelte-kit',
  'storage', 'tmp', '.pnpm-store', 'Pods', '.gradle', 'bin', 'obj', '.dart_tool', '.yarn']);

const MANIFEST_RE = /^(package\.json|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|composer\.json|composer\.lock|requirements[^/]*\.txt|Pipfile\.lock|poetry\.lock|uv\.lock|pdm\.lock|pyproject\.toml|go\.mod|Cargo\.lock|Gemfile|Gemfile\.lock|packages\.lock\.json|.*\.csproj|pom\.xml|gradle\.lockfile|Dockerfile[^/]*|.*\.dockerfile|(docker-)?compose[^/]*\.ya?ml|\.php-version|\.nvmrc|\.node-version|\.python-version|\.ruby-version|\.tool-versions|runtime\.txt|\.go-version)$/i;

/** Optional per-project config: `.patchhero.json` with {"ignore": ["examples", "test/fixtures"]} (directory prefixes relative to the project). */
export function projectConfig(root) {
  const cfg = readJson(path.join(root, '.patchhero.json')) || {};
  const ignore = (Array.isArray(cfg.ignore) ? cfg.ignore : []).map((p) => String(p).replace(/\\/g, '/').replace(/^\.\//, '').replace(/\/\*\*?$/, '').replace(/\/$/, '')).filter(Boolean);
  return { ignore };
}

export function findManifests(root, maxDepth = 4) {
  const found = [];
  const { ignore } = projectConfig(root);
  const ignored = (rel) => ignore.some((p) => rel === p || rel.startsWith(p + '/'));
  const walk = (dir, depth) => {
    let entries; try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (ignore.length && ignored(path.relative(root, full).split(path.sep).join('/'))) continue;
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name)) continue;
        if (e.name === '.github' && depth < maxDepth) { walk(full, depth + 1); continue; }
        if (e.name.startsWith('.')) continue;
        if (depth < maxDepth) walk(full, depth + 1);
      } else if (e.isFile()) {
        const rel = path.relative(root, full).split(path.sep).join('/');
        if (MANIFEST_RE.test(e.name) || /^\.github\/workflows\/[^/]+\.ya?ml$/.test(rel)) found.push(rel);
      }
    }
  };
  walk(root, 0);
  return found.sort();
}

const ECO = { npm: 'npm', composer: 'Packagist', pypi: 'PyPI', go: 'Go', cargo: 'crates.io', gem: 'RubyGems', nuget: 'NuGet', maven: 'Maven' };

/** @returns {{packages: Array, runtimes: Array, notes: string[]}} */
export function inventory(root, files) {
  const packages = []; const runtimes = []; const notes = [];
  const add = (eco, name, version, file, extra = {}) => {
    if (!name || !version) return;
    version = String(version).trim();
    if (!/^v?\d/.test(version)) return; // only resolved versions, never ranges
    packages.push({ ecosystem: eco, name, version: eco === 'Go' || eco === 'Packagist' ? version.replace(/^v/, '') : version, file, dev: !!extra.dev, direct: extra.direct ?? null, manager: extra.manager || null });
  };
  const addRuntime = (product, version, file, line, context, extra = {}) => {
    if (!version) return;
    version = String(version).trim().replace(/^v/, '');
    const m = version.match(/^(\d+(?:\.\d+){0,2})/);
    if (!m) return;
    runtimes.push({ product, version: m[1], exact: m[1].split('.').length === 3, file, line, context, ...extra });
  };

  const lockPresent = {
    npm: files.some((f) => /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml)$/.test(f)),
    composer: files.some((f) => /(^|\/)composer\.lock$/.test(f)),
  };

  for (const rel of files) {
    const full = path.join(root, rel); const base = path.basename(rel); const dirOf = path.dirname(rel);
    const lockIn = (name) => files.includes(dirOf === '.' ? name : `${dirOf}/${name}`);

    // ---- npm family -------------------------------------------------------
    if (base === 'package-lock.json' || base === 'npm-shrinkwrap.json') {
      const j = readJson(full); if (!j) continue;
      const direct = new Set(Object.keys({ ...(j.packages?.['']?.dependencies || {}), ...(j.packages?.['']?.devDependencies || {}) }));
      if (j.packages) {
        for (const [k, v] of Object.entries(j.packages)) {
          if (!k || !v?.version || v.link) continue;
          const name = k.replace(/^.*node_modules\//, '');
          add('npm', name, v.version, rel, { dev: !!v.dev, direct: direct.has(name), manager: 'npm' });
        }
      } else if (j.dependencies) {
        const rec = (deps, dev) => { for (const [n, v] of Object.entries(deps)) { add('npm', n, v.version, rel, { dev: dev || !!v.dev, direct: direct.has(n), manager: 'npm' }); if (v.dependencies) rec(v.dependencies, dev || !!v.dev); } };
        rec(j.dependencies, false);
      }
    } else if (base === 'pnpm-lock.yaml') {
      const t = readText(full) || '';
      const sec = t.split(/^packages:\s*$/m)[1] || '';
      for (const m of sec.matchAll(/^ {2}['"]?\/?((?:@[^/\s'"]+\/)?[^@/\s'"]+)@([^\s'"(:]+)/gm)) add('npm', m[1], m[2], rel, { manager: 'pnpm' });
      for (const m of sec.matchAll(/^ {2}\/((?:@[^/\s]+\/)?[^/\s]+)\/(\d[^\s:_(]*)/gm)) add('npm', m[1], m[2], rel, { manager: 'pnpm' }); // v5 style
    } else if (base === 'yarn.lock') {
      const t = readText(full) || '';
      const berry = /__metadata:/.test(t);
      for (const block of t.split(/\n(?=\S)/)) {
        const head = block.split('\n')[0] || '';
        const nm = head.match(/^"?((?:@[^/@"]+\/)?[^@/"\s,]+)@/); const ver = block.match(/^\s+version:?\s+"?([^"\s]+)"?/m);
        if (nm && ver) add('npm', nm[1], ver[1], rel, { manager: berry ? 'yarn-berry' : 'yarn' });
      }
    } else if (base === 'package.json') {
      const j = readJson(full); if (!j) continue;
      if (!lockIn('package-lock.json') && !lockIn('npm-shrinkwrap.json') && !lockIn('yarn.lock') && !lockIn('pnpm-lock.yaml')) {
        const deps = { ...(j.dependencies || {}), ...(j.devDependencies || {}) };
        let exact = 0;
        for (const [n, v] of Object.entries(deps)) if (/^\d/.test(String(v))) { add('npm', n, v, rel, { dev: !!(j.devDependencies || {})[n], direct: true, manager: 'npm' }); exact++; }
        if (Object.keys(deps).length) notes.push(`${rel}: no lockfile, so only ${exact}/${Object.keys(deps).length} exactly-pinned dependencies could be checked. Run your package manager's install to create a lockfile.`);
      }
      const node = j.engines?.node; if (node) addRuntime('node', String(node).replace(/^[^\d]*/, ''), rel, null, 'constraint', { raw: node });
    }

    // ---- Composer ---------------------------------------------------------
    else if (base === 'composer.lock') {
      const j = readJson(full); if (!j) continue;
      for (const p of j.packages || []) add('Packagist', p.name, p.version, rel, { dev: false, manager: 'composer' });
      for (const p of j['packages-dev'] || []) add('Packagist', p.name, p.version, rel, { dev: true, manager: 'composer' });
      const php = j.platform?.php || j['platform-overrides']?.php; if (php) addRuntime('php', String(php).replace(/^[^\d]*/, ''), rel, null, 'constraint', { raw: php });
    } else if (base === 'composer.json') {
      const j = readJson(full); if (!j) continue;
      if (!lockIn('composer.lock')) {
        const deps = { ...(j.require || {}), ...(j['require-dev'] || {}) };
        for (const [n, v] of Object.entries(deps)) if (n.includes('/') && /^v?\d+\.\d+\.\d+$/.test(String(v))) add('Packagist', n, v, rel, { direct: true, manager: 'composer' });
        if (Object.keys(deps).some((n) => n.includes('/'))) notes.push(`${rel}: no composer.lock, so only exactly-pinned packages could be checked. Run "composer install" to create one.`);
      }
      const plat = j.config?.platform?.php; if (plat) addRuntime('php', plat, rel, null, 'pin', { raw: plat });
      const php = j.require?.php; if (php && !plat) addRuntime('php', String(php).replace(/^[^\d]*/, ''), rel, null, 'constraint', { raw: php });
      if (!php && !plat) { /* a composer project still runs on PHP; record it so runtime advisories reach the user */ runtimes.push({ product: 'php', version: null, exact: false, file: rel, line: null, context: 'implied', raw: null }); }
    }

    // ---- Python -----------------------------------------------------------
    else if (/^requirements.*\.txt$/i.test(base)) {
      const t = readText(full) || '';
      for (const line of t.split('\n')) {
        const l = line.replace(/\s*(#.*)?$/, '').trim(); if (!l || l.startsWith('-')) continue;
        const m = l.match(/^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*===?\s*([^\s;,]+)/);
        if (m) add('PyPI', m[1].toLowerCase(), m[2], rel, { direct: true, manager: 'pip' });
      }
    } else if (base === 'poetry.lock' || base === 'uv.lock' || base === 'pdm.lock') {
      const t = readText(full) || '';
      for (const m of t.matchAll(/^\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"/gm)) add('PyPI', m[1].toLowerCase(), m[2], rel, { manager: base.split('.')[0] });
    } else if (base === 'Pipfile.lock') {
      const j = readJson(full); if (!j) continue;
      for (const [sec, dev] of [['default', false], ['develop', true]]) for (const [n, v] of Object.entries(j[sec] || {})) { const ver = String(v?.version || '').replace(/^==/, ''); add('PyPI', n.toLowerCase(), ver, rel, { dev, manager: 'pipenv' }); }
    } else if (base === 'pyproject.toml') {
      const t = readText(full) || ''; const m = t.match(/requires-python\s*=\s*"([^"]+)"/); if (m) addRuntime('python', m[1].replace(/^[^\d]*/, ''), rel, null, 'constraint', { raw: m[1] });
    }

    // ---- Go ---------------------------------------------------------------
    else if (base === 'go.mod') {
      const t = readText(full) || '';
      const gv = t.match(/^toolchain\s+go(\d+\.\d+(?:\.\d+)?)/m) || t.match(/^go\s+(\d+\.\d+(?:\.\d+)?)/m);
      if (gv) addRuntime('go', gv[1], rel, null, 'pin', { raw: gv[0] });
      const body = (t.match(/require\s*\(([\s\S]*?)\)/g) || []).join('\n') + '\n' + (t.match(/^require\s+\S+\s+\S+.*$/gm) || []).join('\n');
      for (const m of body.matchAll(/^\s*(?:require\s+)?([^\s/]+\/[^\s]+)\s+v?([0-9][^\s]*)(.*)$/gm)) add('Go', m[1], m[2], rel, { direct: !/\/\/\s*indirect/.test(m[3]), manager: 'go' });
    }

    // ---- Rust / Ruby / .NET / Java ----------------------------------------
    else if (base === 'Cargo.lock') {
      const t = readText(full) || '';
      for (const m of t.matchAll(/^\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"/gm)) add('crates.io', m[1], m[2], rel, { manager: 'cargo' });
    } else if (base === 'Gemfile.lock') {
      const t = readText(full) || ''; const specs = (t.split(/^\s*specs:\s*$/m)[1] || '').split(/^\S/m)[0] || '';
      for (const m of specs.matchAll(/^ {4}([A-Za-z0-9_\-.]+) \(([^)\s]+)\)/gm)) add('RubyGems', m[1], m[2], rel, { manager: 'bundler' });
    } else if (base === 'Gemfile') {
      const t = readText(full) || ''; const m = t.match(/^\s*ruby\s+['"]([^'"]+)['"]/m); if (m) addRuntime('ruby', m[1], rel, null, 'pin', { raw: m[0].trim() });
    } else if (base === 'packages.lock.json') {
      const j = readJson(full); if (!j) continue;
      for (const fw of Object.values(j.dependencies || {})) for (const [n, v] of Object.entries(fw)) add('NuGet', n, v?.resolved, rel, { direct: v?.type === 'Direct', manager: 'dotnet' });
    } else if (/\.csproj$/i.test(base) && !lockIn('packages.lock.json')) {
      const t = readText(full) || '';
      for (const m of t.matchAll(/<PackageReference\s+[^>]*Include="([^"]+)"[^>]*Version="([^"$]+)"/g)) add('NuGet', m[1], m[2], rel, { direct: true, manager: 'dotnet' });
    } else if (base === 'pom.xml') {
      const t = readText(full) || '';
      for (const m of t.matchAll(/<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>\s*<version>([^<$]+)<\/version>/g)) add('Maven', `${m[1]}:${m[2]}`, m[3], rel, { direct: true, manager: 'maven' });
    } else if (base === 'gradle.lockfile') {
      const t = readText(full) || '';
      for (const m of t.matchAll(/^([^:#\s]+):([^:\s]+):([^=\s]+)=/gm)) add('Maven', `${m[1]}:${m[2]}`, m[3], rel, { manager: 'gradle' });
    }

    // ---- Containers -------------------------------------------------------
    else if (/^Dockerfile/i.test(base) || /\.dockerfile$/i.test(base)) {
      const t = readText(full) || '';
      t.split('\n').forEach((line, i) => { const m = line.match(/^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)/i); if (m) for (const r of imageRuntimes(m[1])) addRuntime(r.product, r.version, rel, i + 1, 'deploy', { image: m[1], raw: line.trim() }); });
    } else if (/^(docker-)?compose.*\.ya?ml$/i.test(base)) {
      const t = readText(full) || '';
      t.split('\n').forEach((line, i) => { const m = line.match(/^\s*image:\s*['"]?([^'"\s#]+)/); if (m) for (const r of imageRuntimes(m[1])) addRuntime(r.product, r.version, rel, i + 1, 'deploy', { image: m[1], raw: line.trim() }); });
    }

    // ---- Version files ----------------------------------------------------
    else if (base === '.php-version') addRuntime('php', readText(full), rel, 1, 'pin');
    else if (base === '.nvmrc' || base === '.node-version') addRuntime('node', (readText(full) || '').replace(/^lts\/.*/i, ''), rel, 1, 'pin');
    else if (base === '.python-version') addRuntime('python', readText(full), rel, 1, 'pin');
    else if (base === '.ruby-version') addRuntime('ruby', (readText(full) || '').replace(/^ruby-/, ''), rel, 1, 'pin');
    else if (base === '.go-version') addRuntime('go', readText(full), rel, 1, 'pin');
    else if (base === 'runtime.txt') { const t = (readText(full) || '').trim(); const m = t.match(/^(python|php|ruby|node(?:js)?)-?(\d[\d.]*)/i); if (m) addRuntime(m[1].toLowerCase().replace('nodejs', 'node'), m[2], rel, 1, 'pin'); }
    else if (base === '.tool-versions') {
      (readText(full) || '').split('\n').forEach((line, i) => { const m = line.match(/^(php|nodejs|node|python|ruby|golang|go)\s+(\S+)/); if (m) addRuntime(m[1].replace('nodejs', 'node').replace('golang', 'go'), m[2], rel, i + 1, 'pin'); });
    }

    // ---- CI ---------------------------------------------------------------
    else if (/^\.github\/workflows\//.test(rel)) {
      (readText(full) || '').split('\n').forEach((line, i) => { const m = line.match(/^\s*(php|node|python|ruby|go)-version:\s*['"]?(\d[\d.]*)/); if (m) addRuntime(m[1], m[2], rel, i + 1, 'ci'); });
    }
  }

  // De-duplicate packages (same eco+name+version) and runtimes (same product+version+file)
  return {
    packages: uniqBy(packages, (p) => `${p.ecosystem}|${p.name}|${p.version}`),
    runtimes: uniqBy(runtimes, (r) => `${r.product}|${r.version}|${r.file}|${r.line}`),
    notes,
  };
}

const IMAGE_PRODUCTS = { php: 'php', node: 'node', python: 'python', ruby: 'ruby', golang: 'go', nginx: 'nginx', wordpress: 'wordpress' };
export function imageRuntimes(ref) {
  const out = [];
  const [name, tagRaw] = ref.replace(/@sha256:.*$/, '').split(':').length > 2 ? [ref.slice(0, ref.lastIndexOf(':')), ref.slice(ref.lastIndexOf(':') + 1)] : ref.split(':');
  const tag = tagRaw || 'latest';
  const last = name.split('/').pop().toLowerCase();
  const product = IMAGE_PRODUCTS[last] || Object.keys(IMAGE_PRODUCTS).find((k) => new RegExp(`(^|[-_])${k}([-_]|$)`).test(last)) && IMAGE_PRODUCTS[Object.keys(IMAGE_PRODUCTS).find((k) => new RegExp(`(^|[-_])${k}([-_]|$)`).test(last))];
  const lead = tag.match(/^v?(\d+(?:\.\d+){0,2})/);
  if (product && lead) out.push({ product, version: lead[1] });
  else if (product) out.push({ product, version: null }); // "latest" — unpinned
  const php = tag.match(/php[-_]?(\d+\.\d+(?:\.\d+)?)/i); if (php && product !== 'php') out.push({ product: 'php', version: php[1] });
  return out;
}

// Runtimes installed on this machine — only the ones the project actually uses.
function localRuntimes(products) {
  const probes = {
    php: ['php', ['-r', 'echo PHP_VERSION;']],
    node: ['node', ['-p', 'process.versions.node']],
    python: ['python3', ['-c', 'import platform;print(platform.python_version())']],
    ruby: ['ruby', ['-e', 'print RUBY_VERSION']],
    go: ['go', ['version']],
    nginx: ['nginx', ['-v']],
  };
  const out = [];
  for (const p of products) {
    const probe = probes[p]; if (!probe) continue;
    const tryRun = (cmd, args) => { try { return execFileSync(cmd, args, { encoding: 'utf8', timeout: 4000, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true }); } catch (e) { return e?.stderr || null; } };
    let outp = tryRun(probe[0], probe[1]); if (p === 'python' && !outp) outp = tryRun('python', probe[1]);
    const m = String(outp || '').match(/(\d+\.\d+\.\d+)/);
    if (m) out.push({ product: p, version: m[1], exact: true, file: 'this machine', line: null, context: 'local', raw: `${probe[0]} ${probe[1].join(' ')}` });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Feeds
// ---------------------------------------------------------------------------

const RUNTIME_META = {
  php: { eol: 'php', cpe: 'cpe:2.3:a:php:php', label: 'PHP' },
  node: { eol: 'nodejs', cpe: 'cpe:2.3:a:nodejs:node.js', label: 'Node.js' },
  python: { eol: 'python', cpe: 'cpe:2.3:a:python:python', label: 'Python' },
  ruby: { eol: 'ruby', cpe: 'cpe:2.3:a:ruby-lang:ruby', label: 'Ruby' },
  go: { eol: 'go', cpe: 'cpe:2.3:a:golang:go', label: 'Go' },
  nginx: { eol: 'nginx', cpe: 'cpe:2.3:a:f5:nginx', label: 'nginx' },
  wordpress: { eol: 'wordpress', cpe: 'cpe:2.3:a:wordpress:wordpress', label: 'WordPress' },
};

async function feedKev(opts) {
  const cached = cacheGet('kev.json', opts.noCache ? 0 : opts.cacheTtl);
  if (cached) return cached;
  if (opts.offline) return cacheGet('kev.json', null) || { vulnerabilities: [] };
  const j = await http('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', { timeout: opts.timeout * 2 });
  const slim = { catalogVersion: j.catalogVersion, dateReleased: j.dateReleased, count: j.count, vulnerabilities: j.vulnerabilities.map((v) => ({ cveID: v.cveID, vendorProject: v.vendorProject, product: v.product, name: v.vulnerabilityName, dateAdded: v.dateAdded, dueDate: v.dueDate, ransomware: v.knownRansomwareCampaignUse })) };
  cacheSet('kev.json', slim);
  return slim;
}

async function feedEpss(cves, opts) {
  const store = cacheGet('epss.json', null) || {};
  const fresh = (e) => e && Date.now() - e.fetched < DAY;
  const missing = opts.noCache ? cves : cves.filter((c) => !fresh(store[c]));
  if (missing.length && !opts.offline) {
    for (let i = 0; i < missing.length; i += 100) {
      const chunk = missing.slice(i, i + 100);
      try {
        const j = await http(`https://api.first.org/data/v1/epss?cve=${chunk.join(',')}`, { timeout: opts.timeout });
        for (const d of j.data || []) store[d.cve] = { epss: Number(d.epss), percentile: Number(d.percentile), date: d.date, fetched: Date.now() };
        for (const c of chunk) if (!store[c]) store[c] = { epss: null, percentile: null, fetched: Date.now() };
      } catch (e) { log.msg(`EPSS unavailable (${e.message})`); break; }
    }
    cacheSet('epss.json', store);
  }
  return store;
}

async function feedEol(product, opts) {
  const name = `eol-${product}.json`;
  const cached = cacheGet(name, opts.noCache ? 0 : opts.cacheTtl); if (cached) return cached;
  if (opts.offline) return cacheGet(name, null);
  try { const j = await http(`https://endoflife.date/api/${product}.json`, { timeout: opts.timeout }); cacheSet(name, j); return j; } catch (e) { log.msg(`endoflife.date ${product} unavailable (${e.message})`); return cacheGet(name, null); }
}

async function feedNvd(cpe, opts) {
  const name = `nvd-${cpe.replace(/[^a-z0-9]+/gi, '_')}.json`;
  const cached = cacheGet(name, opts.noCache ? 0 : opts.cacheTtl); if (cached) return cached;
  if (opts.offline) return cacheGet(name, null) || [];
  const end = new Date(); const start = new Date(end.getTime() - 119 * DAY);
  const fmt = (d) => d.toISOString().replace(/\.\d{3}Z$/, '.000Z');
  const headers = process.env.NVD_API_KEY ? { apiKey: process.env.NVD_API_KEY } : {};
  try {
    const j = await http(`https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=${encodeURIComponent(cpe)}&pubStartDate=${fmt(start)}&pubEndDate=${fmt(end)}&resultsPerPage=200`, { timeout: opts.timeout * 2, headers });
    const slim = (j.vulnerabilities || []).map(({ cve }) => {
      const m = cve.metrics || {}; const pick = (m.cvssMetricV40 || m.cvssMetricV31 || m.cvssMetricV30 || [])[0];
      const ranges = [];
      for (const cfg of cve.configurations || []) for (const node of cfg.nodes || []) for (const cm of node.cpeMatch || []) {
        if (!cm.vulnerable || !cm.criteria.startsWith(cpe + ':')) continue;
        const exact = cm.criteria.split(':')[5];
        ranges.push({ exact: exact && exact !== '*' && exact !== '-' ? exact : null, startInc: cm.versionStartIncluding, startExc: cm.versionStartExcluding, endInc: cm.versionEndIncluding, endExc: cm.versionEndExcluding });
      }
      return { id: cve.id, published: cve.published, summary: ((cve.descriptions || []).find((d) => d.lang === 'en')?.value || '').replace(/\s+/g, ' ').trim(), cvss: pick?.cvssData?.baseScore ?? null, severity: pick?.cvssData?.baseSeverity || null, ranges };
    });
    cacheSet(name, slim); return slim;
  } catch (e) { log.msg(`NVD unavailable for ${cpe} (${e.message})`); return cacheGet(name, null) || []; }
}

async function feedOsv(packages, opts) {
  // 1) which vuln ids affect each package@version
  const results = new Array(packages.length).fill(null);
  if (!opts.offline) {
    for (let i = 0; i < packages.length; i += 500) {
      const chunk = packages.slice(i, i + 500);
      try {
        const j = await http('https://api.osv.dev/v1/querybatch', { method: 'POST', body: { queries: chunk.map((p) => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version })) }, timeout: opts.timeout * 2 });
        j.results.forEach((r, k) => { results[i + k] = r.vulns || []; });
      } catch (e) { log.msg(`OSV unavailable (${e.message})`); }
    }
  }
  // 2) details per vuln id, cached by id + modified stamp
  const ids = uniqBy(results.flatMap((r) => r || []), (v) => v.id);
  const details = {};
  await pMap(ids, async ({ id, modified }) => {
    const name = `osv/${id}.json`; const c = cacheGet(name, null);
    if (c && c.modified === modified) { details[id] = c; return; }
    if (opts.offline) { if (c) details[id] = c; return; }
    try { const j = await http(`https://api.osv.dev/v1/vulns/${id}`, { timeout: opts.timeout }); details[id] = j; cacheSet(name, j); } catch (e) { if (c) details[id] = c; }
  }, 8);
  return { results, details };
}

// ---------------------------------------------------------------------------
// CVSS 3.x base score from a vector (OSV gives vectors, not scores)
// ---------------------------------------------------------------------------

export function cvss3Score(vector) {
  if (!/^CVSS:3\.[01]\//.test(vector || '')) return null;
  const v = Object.fromEntries(vector.split('/').slice(1).map((kv) => kv.split(':')));
  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[v.AV], AC = { L: 0.77, H: 0.44 }[v.AC], UI = { N: 0.85, R: 0.62 }[v.UI];
  const changed = v.S === 'C';
  const PR = { N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 }[v.PR];
  const CIA = { H: 0.56, L: 0.22, N: 0 };
  if ([AV, AC, UI, PR].some((x) => x == null)) return null;
  const iss = 1 - (1 - CIA[v.C]) * (1 - CIA[v.I]) * (1 - CIA[v.A]);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const expl = 8.22 * AV * AC * PR * UI;
  const roundup = (x) => { const i = Math.round(x * 100000); return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10; };
  if (impact <= 0) return 0;
  return roundup(Math.min(changed ? 1.08 * (impact + expl) : impact + expl, 10));
}
const SEVERITY_FALLBACK = { CRITICAL: 9.5, HIGH: 8.0, MODERATE: 5.5, MEDIUM: 5.5, LOW: 2.5 };

// ---------------------------------------------------------------------------
// Prioritisation — the "traction" score. Keep in sync with references/priority.md
// ---------------------------------------------------------------------------

export const LEVELS = ['P0', 'P1', 'P2', 'P3'];
export const LEVEL_LABEL = { P0: 'Patch today', P1: 'Patch this week', P2: 'Next release', P3: 'Backlog' };

export function prioritize(f) {
  const reasons = [];
  let level;
  const cvss = f.cvss;
  if (cvss == null) level = 2; else if (cvss >= 9) level = 0; else if (cvss >= 7) level = 1; else if (cvss >= 4) level = 2; else level = 3;
  if (cvss != null) reasons.push(`CVSS ${cvss} ${f.severity ? f.severity.toLowerCase() : ''}`.trim());

  if (f.kev) { level = 0; reasons.unshift(`in CISA KEV (exploited in the wild, added ${f.kev.dateAdded})${f.kev.ransomware === 'Known' ? ', used by ransomware' : ''}`); }

  if (f.epss != null) {
    const pct = Math.round(f.epss.percentile * 100);
    if (f.epss.epss >= 0.3) { level = 0; reasons.push(`EPSS ${(f.epss.epss * 100).toFixed(0)}% chance of exploitation in 30 days (top ${100 - pct}%)`); }
    else if (f.epss.epss >= 0.05) { level = Math.min(level, 1); reasons.push(`EPSS ${(f.epss.epss * 100).toFixed(1)}% (top ${100 - pct}% of all CVEs)`); }
  }

  const age = daysAgo(f.published);
  if (age != null && age <= 14 && cvss != null && cvss >= 7) { level = Math.max(0, level - 1); reasons.push(`disclosed ${age === 0 ? 'today' : age === 1 ? 'yesterday' : age + ' days ago'}`); }
  // A vendor emergency release only counts for the CVEs it was shipped for (fresh ones), not every old CVE on the same runtime.
  if (f.emergencyRelease && age != null && age <= 30) { level = Math.max(0, level - 1); reasons.push(`vendor shipped an emergency release on ${f.emergencyRelease}`); }

  if (f.dev && !f.kev) { level = Math.min(3, level + 1); reasons.push('dev-only dependency'); }
  if (f.context === 'constraint' || f.context === 'ci' || f.context === 'implied') reasons.push('deployed version not pinned in repo — verify on the server');
  if (!f.fixedVersion && f.fixAvailable === false) reasons.push('no fix published yet — mitigate (WAF, disable feature) and watch');

  return { level: LEVELS[level], label: LEVEL_LABEL[LEVELS[level]], reasons };
}

// ---------------------------------------------------------------------------
// Patch plan: the exact command for this ecosystem / manager
// ---------------------------------------------------------------------------

function packageFix(p, fixed) {
  const v = fixed || 'latest';
  switch (p.ecosystem) {
    case 'npm':
      if (p.manager === 'pnpm') return p.direct === false ? [`Add to package.json: "pnpm": { "overrides": { "${p.name}": ">=${v}" } }`, 'pnpm install'] : [`pnpm up ${p.name}@${v}`];
      if (p.manager === 'yarn-berry') return p.direct === false ? [`Add to package.json: "resolutions": { "${p.name}": "${v}" }`, 'yarn install'] : [`yarn up ${p.name}@${v}`];
      if (p.manager === 'yarn') return p.direct === false ? [`Add to package.json: "resolutions": { "${p.name}": "${v}" }`, 'yarn install'] : [`yarn upgrade ${p.name}@${v}`];
      return p.direct === false ? [`Add to package.json: "overrides": { "${p.name}": ">=${v}" }`, 'npm install'] : [`npm install ${p.name}@${v}`];
    case 'Packagist': return p.direct === false ? [`composer update ${p.name} --with-all-dependencies`] : [`composer require ${p.name}:^${v} --update-with-all-dependencies`];
    case 'PyPI':
      if (p.manager === 'poetry') return [`poetry add "${p.name}>=${v}"`];
      if (p.manager === 'uv') return [`uv add "${p.name}>=${v}"`];
      if (p.manager === 'pipenv') return [`pipenv install "${p.name}>=${v}"`];
      if (p.manager === 'pdm') return [`pdm add "${p.name}>=${v}"`];
      return [`Change the pin in ${p.file} to ${p.name}==${v}`, `pip install -r ${p.file}`];
    case 'Go': return [`go get ${p.name}@v${v} && go mod tidy`];
    case 'crates.io': return [`cargo update -p ${p.name} --precise ${v}`];
    case 'RubyGems': return [`bundle update ${p.name} --conservative`];
    case 'NuGet': return [`dotnet add package ${p.name} --version ${v}`];
    case 'Maven': return p.manager === 'gradle' ? [`Set ${p.name} to ${v} in your Gradle dependencies, then ./gradlew dependencies --write-locks`] : [`Set <version>${v}</version> for ${p.name} in ${p.file}`];
    default: return [`Upgrade ${p.name} to ${v}`];
  }
}

function runtimeFix(r, latest) {
  const label = RUNTIME_META[r.product]?.label || r.product;
  switch (r.context) {
    case 'deploy': {
      if (!r.version) return [`${r.file}:${r.line} uses an unpinned ${label} image tag — pin it (e.g. ${r.product}:${latest}) and rebuild`];
      if (r.exact) return [`${r.file}:${r.line}: change ${r.version} → ${latest}`, 'Rebuild and redeploy the image'];
      return [`${r.file}:${r.line} uses a floating tag (${r.image || r.version}); rebuild with --pull so it picks up ${latest}, then redeploy`, `Verify inside the container: ${r.product === 'go' ? 'go version' : r.product + ' -v'}`];
    }
    case 'pin': return [`${r.file}${r.line ? ':' + r.line : ''}: change ${r.version} → ${latest}`, `Reinstall the runtime locally and in CI/hosting so the pin takes effect`];
    case 'local': return [`Upgrade ${label} on this machine to ${latest} (${process.platform === 'win32' ? 'winget/choco or the installer' : process.platform === 'darwin' ? 'brew upgrade' : 'apt/dnf or your version manager'})`];
    case 'ci': return [`${r.file}:${r.line}: CI installs the newest patch automatically; verify the deployed server, not CI`];
    default: return [`Check the ${label} version on every server/host running this app (${r.product === 'go' ? 'go version' : r.product + ' -v'}); fixed releases: ${latest} (pick the one on your line)`, `Managed hosting: switch the ${label} version in the control panel · Docker: rebuild from a patched base image · OS packages: apt/dnf upgrade ${r.product}`];
  }
}

// ---------------------------------------------------------------------------
// The scan
// ---------------------------------------------------------------------------

function inRange(version, r) {
  const c = (a, b) => cmpVersions(a, b);
  if (r.exact) return c(version, r.exact) === 0;
  if (r.startInc && c(version, r.startInc) < 0) return false;
  if (r.startExc && c(version, r.startExc) <= 0) return false;
  if (r.endInc && c(version, r.endInc) > 0) return false;
  if (r.endExc && c(version, r.endExc) >= 0) return false;
  return !!(r.startInc || r.startExc || r.endInc || r.endExc);
}
function lineMatches(line, r) {
  // Floating version like "8.3": does any range touch the 8.3.x line?
  const lo = line, hi = line + '.999999';
  if (r.exact) return r.exact.startsWith(line + '.') || r.exact === line;
  const startOk = !(r.endInc && cmpVersions(lo, r.endInc) > 0) && !(r.endExc && cmpVersions(lo, r.endExc) >= 0);
  const endOk = !(r.startInc && cmpVersions(hi, r.startInc) < 0) && !(r.startExc && cmpVersions(hi, r.startExc) <= 0);
  return startOk && endOk && !!(r.startInc || r.startExc || r.endInc || r.endExc);
}

export async function scanProject(root, opts) {
  const started = Date.now();
  const files = findManifests(root);
  const inv = inventory(root, files);
  const notes = [...inv.notes];
  const products = uniqBy(inv.runtimes.map((r) => r.product), (x) => x);
  if (opts.local && products.length) inv.runtimes.push(...localRuntimes(products));

  if (!inv.packages.length && !inv.runtimes.length) return { root, files, inventory: inv, findings: [], notes: ['No dependency manifests, lockfiles, Dockerfiles or runtime version files found.'], empty: true, durationMs: Date.now() - started };

  log.msg(`${path.basename(root)}: ${inv.packages.length} packages, ${inv.runtimes.length} runtime refs across ${files.length} files`);

  // --- feeds (in parallel) --------------------------------------------------
  const runtimeProducts = uniqBy(inv.runtimes.map((r) => r.product), (x) => x).filter((p) => RUNTIME_META[p]);
  const [kev, osv, eols, nvds] = await Promise.all([
    feedKev(opts).catch((e) => { log.msg(`KEV unavailable (${e.message})`); return cacheGet('kev.json', null) || { vulnerabilities: [] }; }),
    feedOsv(inv.packages, opts),
    Promise.all(runtimeProducts.map((p) => feedEol(RUNTIME_META[p].eol, opts))),
    Promise.all(runtimeProducts.map((p) => feedNvd(RUNTIME_META[p].cpe, opts))),
  ]);
  const kevById = new Map((kev.vulnerabilities || []).map((v) => [v.cveID, v]));
  const eolByProduct = Object.fromEntries(runtimeProducts.map((p, i) => [p, eols[i]]));
  const nvdByProduct = Object.fromEntries(runtimeProducts.map((p, i) => [p, nvds[i]]));

  const findings = [];

  // --- package findings -----------------------------------------------------
  inv.packages.forEach((p, i) => {
    for (const { id } of osv.results[i] || []) {
      const d = osv.details[id]; if (!d) continue;
      const aliases = d.aliases || []; const cves = [id, ...aliases].filter((x) => /^CVE-/.test(x));
      const vector = (d.severity || []).find((s) => /^CVSS_V3/.test(s.type))?.score;
      let cvss = vector ? cvss3Score(vector) : null;
      const sevLabel = (d.database_specific?.severity || '').toUpperCase();
      if (cvss == null && SEVERITY_FALLBACK[sevLabel]) cvss = SEVERITY_FALLBACK[sevLabel];
      // fixed version: smallest "fixed" greater than the installed version
      const fixedCandidates = [];
      for (const a of d.affected || []) {
        if (a.package?.ecosystem !== p.ecosystem || a.package?.name?.toLowerCase() !== p.name.toLowerCase()) continue;
        for (const r of a.ranges || []) for (const ev of r.events || []) if (ev.fixed && cmpVersions(ev.fixed, p.version) > 0) fixedCandidates.push(ev.fixed);
      }
      fixedCandidates.sort(cmpVersions);
      const major = String(p.version).replace(/^v/, '').split('.')[0];
      findings.push({
        kind: 'package', ecosystem: p.ecosystem, name: p.name, version: p.version, file: p.file, dev: p.dev, direct: p.direct, manager: p.manager,
        id, cves, title: cleanTitle(d.summary || d.details || id), published: d.published, cvss, severity: sevLabel || null,
        fixedVersion: fixedCandidates[0] || null, fixedSameMajor: fixedCandidates.find((v) => String(v).replace(/^v/, '').split('.')[0] === major) || null,
        fixAvailable: fixedCandidates.length > 0,
        url: `https://osv.dev/vulnerability/${id}`,
      });
    }
  });

  // --- runtime findings -----------------------------------------------------
  // The same constraint can appear in composer.json and composer.lock; report it once.
  const runtimeRefs = uniqBy(inv.runtimes, (r) => (r.context === 'constraint' || r.context === 'implied') ? `${r.product}|${r.version}|${r.context}` : `${r.product}|${r.version}|${r.file}|${r.line}`);
  const supported = (eol) => eol.filter((c) => c.eol === false || (typeof c.eol === 'string' && Date.parse(c.eol) > Date.now()));
  for (const r of runtimeRefs) {
    const meta = RUNTIME_META[r.product]; if (!meta) continue;
    const eol = eolByProduct[r.product] || [];
    const line = r.version ? cycleOf(r.product, r.version) : null;
    const cycle = line ? eol.find((c) => String(c.cycle) === line) || eol.find((c) => String(c.cycle) === line.split('.')[0]) : null;
    const isEol = !!(cycle && typeof cycle.eol === 'string' && Date.parse(cycle.eol) < Date.now());
    // Exact pin or floating tag: the fix is this line's latest. Constraint like ^8.2: any supported line at/after it.
    let latest = cycle?.latest || null;
    if (r.context === 'constraint' || r.context === 'implied') {
      const lines = supported(eol).filter((c) => !line || cmpVersions(String(c.cycle), line) >= 0).map((c) => c.latest).filter(Boolean).sort(cmpVersions);
      if (lines.length) latest = lines.join(' / ');
    }
    const emergency = cycle && daysAgo(cycle.latestReleaseDate) != null && daysAgo(cycle.latestReleaseDate) <= 14 ? cycle.latestReleaseDate : null;
    const behind = cycle?.latest && r.version && r.exact && cmpVersions(r.version, cycle.latest) < 0;

    for (const cve of nvdByProduct[r.product] || []) {
      let affected;
      if (!r.version) affected = 'unknown';
      else if (r.exact) affected = cve.ranges.some((rg) => inRange(r.version, rg)) ? 'yes' : 'no';
      else affected = cve.ranges.some((rg) => lineMatches(line, rg)) ? 'maybe' : 'no';
      if (affected === 'no') continue;
      // Unpinned contexts only surface CVEs that are hot: critical/high and fresh, or in KEV.
      const hot = kevById.has(cve.id) || ((cve.cvss ?? 0) >= 7 && (daysAgo(cve.published) ?? 999) <= 30);
      if (affected !== 'yes' && !hot) continue;
      if (r.context === 'ci' && !isEol) continue; // CI runners install the newest patch themselves
      findings.push({
        kind: 'runtime', product: r.product, productLabel: meta.label, version: r.version, exact: r.exact, context: r.context, file: r.file, line: r.line, image: r.image, raw: r.raw,
        id: cve.id, cves: [cve.id], title: cleanTitle(cve.summary), published: cve.published, cvss: cve.cvss, severity: cve.severity,
        fixedVersion: latest, fixAvailable: !!latest, affected, emergencyRelease: emergency, eolCycle: isEol ? cycle.cycle : null,
        url: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
      });
    }
    if (isEol && r.context !== 'ci' && r.context !== 'constraint') notes.push(`${meta.label} ${cycle.cycle} (${r.file}${r.line ? ':' + r.line : ''}) reached end-of-life on ${cycle.eol}: it gets no security fixes at all. Plan a move to ${moveTarget(r.product, supported(eol))}.`);
    if (behind && !findings.some((f) => f.kind === 'runtime' && f.file === r.file && f.line === r.line)) notes.push(`${meta.label} ${r.version} (${r.file}${r.line ? ':' + r.line : ''}) is behind the latest ${cycle.cycle} release ${cycle.latest} (${cycle.latestReleaseDate}); no recent CVE matched, but staying current is cheap.`);
  }

  // --- enrichment: KEV + EPSS -------------------------------------------------
  const allCves = uniqBy(findings.flatMap((f) => f.cves), (x) => x);
  const epss = await feedEpss(allCves, opts);
  for (const f of findings) {
    const kevHit = f.cves.map((c) => kevById.get(c)).find(Boolean);
    f.kev = kevHit ? { dateAdded: kevHit.dateAdded, dueDate: kevHit.dueDate, ransomware: kevHit.ransomware } : null;
    const scores = f.cves.map((c) => epss[c]).filter((e) => e && e.epss != null);
    f.epss = scores.length ? scores.reduce((a, b) => (b.epss > a.epss ? b : a)) : null;
    const pr = prioritize(f); f.priority = pr.level; f.priorityLabel = pr.label; f.reasons = pr.reasons;
  }

  // The same CVE often arrives twice (GHSA and PYSEC both alias it). Keep the richer record.
  const byPriority = (a, b) => LEVELS.indexOf(a.priority) - LEVELS.indexOf(b.priority) || (b.cvss ?? 0) - (a.cvss ?? 0);
  findings.sort((a, b) => byPriority(a, b) || (b.title.length < 140 ? 1 : 0) - (a.title.length < 140 ? 1 : 0));
  const deduped = uniqBy(findings, (f) => `${f.kind}|${f.name || f.product}|${f.version}|${f.cves[0] || f.id}|${f.file}|${f.line || ''}`);

  const groups = groupFindings(deduped);
  return {
    root, files, inventory: { packages: inv.packages.length, runtimes: inv.runtimes }, findings: deduped, groups, notes,
    sources: { kev: { catalogVersion: kev.catalogVersion, count: kev.count }, epssDate: Object.values(epss)[0]?.date || null, nvdWindowDays: 119, scannedAt: new Date().toISOString() },
    durationMs: Date.now() - started,
  };
}

function cycleOf(product, version) {
  const parts = version.split('.');
  return product === 'node' ? parts[0] : parts.slice(0, 2).join('.');
}
/** First sentence, whitespace collapsed, at most 140 chars. Advisory texts can run to paragraphs. */
function cleanTitle(text) {
  const t = String(text || '').replace(/\s+/g, ' ').trim();
  const first = t.match(/^.{20,}?[.!?](?=\s|$)/)?.[0] || t;
  return first.length > 140 ? first.slice(0, 137) + '…' : first;
}
/** The line a user should move to when theirs is end-of-life: the newest supported one (newest LTS for Node). */
function moveTarget(product, supportedCycles) {
  const sorted = [...supportedCycles].sort((a, b) => cmpVersions(String(a.cycle), String(b.cycle)));
  if (product === 'node') { const lts = sorted.filter((c) => c.lts === true || (typeof c.lts === 'string' && Date.parse(c.lts) <= Date.now())); if (lts.length) return lts[lts.length - 1].cycle; }
  return sorted.length ? sorted[sorted.length - 1].cycle : 'a supported line';
}

/**
 * One entry per component (package@version in a file, or runtime ref) so a
 * reader sees "upgrade guzzle to 7.15.2: fixes 14 advisories" instead of 14 rows.
 * The group takes the worst finding's priority and reasons, and the highest
 * fixed version so that one upgrade closes everything.
 */
export function groupFindings(findings) {
  const map = new Map();
  for (const f of findings) {
    const key = f.kind === 'package' ? `pkg|${f.ecosystem}|${f.name}|${f.version}|${f.file}` : `rt|${f.product}|${f.version}|${f.context}|${f.file}|${f.line || ''}`;
    if (!map.has(key)) map.set(key, { ...f, findings: [], cves: [], reasons: [], id: undefined, title: undefined, url: undefined, published: undefined });
    const g = map.get(key); g.findings.push(f);
  }
  const groups = [];
  for (const g of map.values()) {
    g.findings.sort((a, b) => LEVELS.indexOf(a.priority) - LEVELS.indexOf(b.priority) || (b.cvss ?? 0) - (a.cvss ?? 0));
    const worst = g.findings[0];
    g.worst = worst; g.priority = worst.priority; g.priorityLabel = worst.priorityLabel; g.cvss = worst.cvss;
    g.cves = uniqBy(g.findings.flatMap((x) => (x.cves.length ? x.cves : [x.id])), (x) => x);
    g.kev = g.findings.find((x) => x.kev)?.kev || null;
    g.reasons = uniqBy(worst.reasons.concat(g.findings.length > 1 ? [`${g.findings.length} advisories on this version`] : []), (x) => x);
    if (g.kind === 'package') {
      // Prefer the smallest upgrade that closes everything: stay on the same major when every advisory has a fix there.
      const withFix = g.findings.filter((x) => x.fixedVersion);
      const sameMajor = withFix.map((x) => x.fixedSameMajor);
      const anyFix = withFix.map((x) => x.fixedVersion).sort(cmpVersions);
      g.unfixed = g.findings.length - withFix.length;
      g.fixAvailable = withFix.length > 0;
      if (withFix.length && sameMajor.every(Boolean)) { g.fixedVersion = sameMajor.sort(cmpVersions)[sameMajor.length - 1]; g.majorJump = false; }
      else if (withFix.length) {
        g.fixedVersion = anyFix[anyFix.length - 1]; g.majorJump = true;
        const covered = sameMajor.filter(Boolean).sort(cmpVersions);
        if (covered.length) g.partialFix = { version: covered[covered.length - 1], covers: covered.length, of: withFix.length, needsMajor: withFix.filter((x) => !x.fixedSameMajor).map((x) => x.cves[0] || x.id) };
      } else g.fixedVersion = null;
      g.fix = packageFix(g, g.fixedVersion);
    } else {
      g.fixedVersion = worst.fixedVersion; g.fix = runtimeFix(g, g.fixedVersion || 'the latest patch release');
    }
    groups.push(g);
  }
  groups.sort((a, b) => LEVELS.indexOf(a.priority) - LEVELS.indexOf(b.priority) || (b.cvss ?? 0) - (a.cvss ?? 0) || String(a.name || a.product).localeCompare(String(b.name || b.product)));
  return groups;
}

function summarize(groups) { const s = { P0: 0, P1: 0, P2: 0, P3: 0, cves: 0 }; for (const g of groups) { s[g.priority]++; s.cves += g.cves.length; } return s; }

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

const C = { reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m', red: '\x1b[31m', yellow: '\x1b[33m', green: '\x1b[32m', cyan: '\x1b[36m', magenta: '\x1b[35m' };
const PCOLOR = { P0: 'red', P1: 'yellow', P2: 'cyan', P3: 'dim' };
function paint(opts, color, s) { return opts.color ? `${C[color]}${s}${C.reset}` : s; }

function subject(f) {
  if (f.kind === 'package') return `${f.name} ${f.version} (${f.file}${f.dev ? ', dev' : ''})`;
  const where = f.file === 'this machine' ? 'installed on this machine' : `${f.file}${f.line ? ':' + f.line : ''}`;
  return `${f.productLabel} ${f.version || '(version not pinned)'} (${where})`;
}
function fixLine(g) {
  if (!g.fixedVersion) return g.kind === 'package' ? '→ no fixed version yet' : '';
  let s = `→ ${g.fixedVersion}`;
  if (g.majorJump) s += g.partialFix ? ` (major upgrade; ${g.partialFix.version} on your current line fixes ${g.partialFix.covers}/${g.partialFix.of}, ${g.partialFix.needsMajor.slice(0, 2).join(', ')} need${g.partialFix.needsMajor.length === 1 ? 's' : ''} the newer line)` : ' (major upgrade; no fix on your current line)';
  if (g.unfixed) s += ` (${g.unfixed} advisor${g.unfixed === 1 ? 'y' : 'ies'} still unfixed upstream)`;
  return s;
}
function cveSummary(g) {
  const w = g.worst; const head = `${w.cves[0] || w.id}: ${w.title}`;
  const rest = g.cves.filter((c) => c !== (w.cves[0] || w.id));
  return rest.length ? `${head} (+${rest.length} more: ${rest.slice(0, 4).join(', ')}${rest.length > 4 ? ', …' : ''})` : head;
}
const plural = (n, s) => `${n} ${s}${n === 1 ? '' : 's'}`;

export function renderHuman(reports, opts) {
  const out = [];
  const multi = reports.length > 1;
  for (const rep of reports) {
    const groups = rep.groups || [];
    const s = summarize(groups);
    const name = path.basename(rep.root) || rep.root;
    if (rep.empty) { out.push(`${paint(opts, 'bold', name)}: ${rep.notes[0]}`); continue; }
    const head = `${paint(opts, 'bold', name)} — ${rep.inventory.packages} packages, ${rep.inventory.runtimes.length} runtime refs · ${plural(groups.length, 'component')} to patch covering ${plural(s.cves, 'CVE')} · ` +
      LEVELS.map((l) => paint(opts, PCOLOR[l], `${l}:${s[l]}`)).join(' ');
    out.push(head);
    const shown = groups.filter((g) => LEVELS.indexOf(g.priority) <= LEVELS.indexOf(opts.min));
    if (!shown.length) out.push(paint(opts, 'green', '  ✔ nothing at or above ' + opts.min));
    let lastLevel = null;
    for (const g of shown) {
      if (g.priority !== lastLevel) { out.push(''); out.push(paint(opts, PCOLOR[g.priority], `${g.priority}  ${LEVEL_LABEL[g.priority].toUpperCase()}`)); lastLevel = g.priority; }
      out.push(`  ${paint(opts, 'bold', subject(g))} ${paint(opts, 'green', fixLine(g))}`);
      out.push(`    ${cveSummary(g)}`);
      out.push(`    ${paint(opts, 'dim', 'why: ' + g.reasons.join(' · '))}`);
      for (const line of g.fix) out.push(`    ${paint(opts, 'cyan', '$')} ${line}`);
    }
    if (rep.notes.length) { out.push(''); for (const n of rep.notes) out.push(paint(opts, 'dim', `  note: ${n}`)); }
    if (multi) out.push('');
  }
  const last = reports[reports.length - 1];
  if (last?.sources) out.push(paint(opts, 'dim', `\nSources: OSV.dev · NVD (last ${last.sources.nvdWindowDays} days) · endoflife.date · CISA KEV ${last.sources.kev.catalogVersion || ''} · EPSS ${last.sources.epssDate || ''} · scanned ${last.sources.scannedAt}`));
  return out.join('\n');
}

export function renderMarkdown(reports) {
  const out = [];
  for (const rep of reports) {
    const groups = rep.groups || []; const s = summarize(groups); const name = path.basename(rep.root) || rep.root;
    out.push(`## ${name}: ${plural(s.P0, 'component')} to patch today, ${s.P1} this week`);
    if (rep.empty) { out.push(rep.notes[0]); continue; }
    const shown = groups.filter((g) => g.priority !== 'P3');
    if (shown.length) {
      out.push('', '| Priority | Component | Vulnerabilities | Why now | Fix |', '|---|---|---|---|---|');
      for (const g of shown) out.push(`| **${g.priority}** ${g.priorityLabel} | ${subject(g)} | [${g.worst.cves[0] || g.worst.id}](${g.worst.url}) ${g.worst.title.replace(/\|/g, '\\|')}${g.cves.length > 1 ? ` (+${g.cves.length - 1} more)` : ''} | ${g.reasons.join('; ')} | ${fixLine(g)} \`${g.fix[0].replace(/`/g, '')}\` |`);
    } else out.push('', 'Nothing above P3. ✔');
    if (rep.notes.length) { out.push('', '**Notes**', ...rep.notes.map((n) => `- ${n}`)); }
    out.push('');
  }
  const last = reports[reports.length - 1];
  if (last?.sources) out.push(`<sub>Sources: OSV.dev, NVD, endoflife.date, CISA KEV ${last.sources.kev.catalogVersion || ''}, FIRST EPSS ${last.sources.epssDate || ''}. Scanned ${last.sources.scannedAt} by patchhero ${VERSION}.</sub>`);
  return out.join('\n');
}

/** Compact block for a Claude Code SessionStart hook. Empty string when nothing urgent. */
export function renderHook(rep, scriptPath) {
  const groups = rep.groups || [];
  const urgent = groups.filter((g) => g.priority === 'P0' || g.priority === 'P1');
  if (!urgent.length) return '';
  const s = summarize(groups);
  const lines = ['<patchhero-alert>',
    `patchhero: ${plural(s.P0, 'component')} to patch TODAY and ${s.P1} to patch this week in this project (${s.P2 + s.P3} lower priority, ${plural(s.cves, 'CVE')} in total). Scanned ${rep.sources?.scannedAt || 'now'}.`];
  for (const g of urgent.slice(0, 8)) lines.push(`${g.priority} ${subject(g)} ${fixLine(g)} — ${g.worst.cves[0] || g.worst.id}: ${g.worst.title.slice(0, 120)}${g.cves.length > 1 ? ` (+${g.cves.length - 1} more)` : ''} [${g.reasons.slice(0, 3).join('; ')}] fix: ${g.fix[0]}`);
  if (urgent.length > 8) lines.push(`…and ${urgent.length - 8} more P0/P1 components.`);
  lines.push(`Before doing anything else, tell the user about the P0 items in one short paragraph and offer to run the patchhero skill to apply the fixes. Do not patch silently. Full report: node "${scriptPath}" "${rep.root}"`, '</patchhero-alert>');
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

function isProjectDir(dir) { try { return findManifests(dir, 2).length > 0; } catch { return false; } }
function hasOwnManifests(dir) { try { return findManifests(dir, 0).length > 0; } catch { return false; } }
function isRepo(dir) { return fs.existsSync(path.join(dir, '.git')); }
function childProjects(dir) {
  try { return fs.readdirSync(dir, { withFileTypes: true }).filter((e) => e.isDirectory() && !SKIP_DIRS.has(e.name) && !e.name.startsWith('.')).map((e) => path.join(dir, e.name)).filter(isProjectDir); } catch { return []; }
}
// A folder like ~/projects: no manifests of its own, not a repo, but holds repos. A monorepo stays one project.
function looksLikeProjectFolder(dir) { return !hasOwnManifests(dir) && !isRepo(dir) && childProjects(dir).some(isRepo); }

export async function main(argv = process.argv.slice(2)) {
  let opts;
  try { opts = parseArgs(argv); } catch (e) { process.stderr.write(e.message + '\n' + HELP); return 1; }
  if (opts.help) { process.stdout.write(HELP); return 0; }
  if (opts.version) { process.stdout.write(VERSION + '\n'); return 0; }
  log.quiet = opts.quiet;
  if (!LEVELS.includes(opts.min)) { process.stderr.write(`--min must be one of ${LEVELS.join(', ')}\n`); return 1; }

  let targets = opts.dirs.map((d) => path.resolve(d));
  if (opts.all) targets = targets.flatMap((d) => childProjects(d));
  else targets = targets.flatMap((d) => (looksLikeProjectFolder(d) ? (log.msg(`${d} holds ${childProjects(d).length} projects; scanning each`), childProjects(d)) : [d]));

  const reports = [];
  for (const t of targets) {
    try { reports.push(await scanProject(t, opts)); }
    catch (e) { reports.push({ root: t, files: [], inventory: { packages: 0, runtimes: [] }, findings: [], groups: [], notes: [`scan failed: ${e.message}`], empty: true, error: true }); }
  }

  const all = reports.flatMap((r) => r.groups || []);
  if (opts.hook) {
    const text = reports.map((r) => renderHook(r, SELF)).filter(Boolean).join('\n');
    if (text) process.stdout.write(text + '\n');
  } else if (opts.json) {
    process.stdout.write(JSON.stringify({ version: VERSION, summary: summarize(all), projects: reports.map((r) => ({ ...r, groups: (r.groups || []).map(({ findings, worst, ...g }) => ({ ...g, worstId: worst?.id })) })) }, null, 2) + '\n');
  } else if (opts.md) {
    process.stdout.write(renderMarkdown(reports) + '\n');
  } else {
    process.stdout.write(renderHuman(reports, opts) + '\n');
  }

  if (opts.failOn !== 'NONE' && LEVELS.includes(opts.failOn)) {
    const worst = all.reduce((w, f) => Math.min(w, LEVELS.indexOf(f.priority)), 99);
    if (worst <= LEVELS.indexOf(opts.failOn)) return 2;
  }
  return reports.some((r) => r.error) ? 1 : 0;
}

const invokedDirectly = process.argv[1] && path.resolve(process.argv[1]) === SELF;
if (invokedDirectly) main().then((code) => process.exit(code), (e) => { process.stderr.write(`patchhero: ${e.stack || e}\n`); process.exit(1); });
