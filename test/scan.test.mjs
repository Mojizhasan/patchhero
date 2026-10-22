// Offline tests: parsers, version comparison, CVSS math, prioritisation, grouping.
// Run with: node --test test/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { inventory, findManifests, cmpVersions, cvss3Score, prioritize, imageRuntimes, groupFindings, LEVELS } from '../skills/patchnow/scripts/scan.mjs';

const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures');
const inv = (name) => { const root = path.join(FIX, name); return inventory(root, findManifests(root)); };
const pkg = (i, eco, name) => i.packages.find((p) => p.ecosystem === eco && p.name === name);

test('cmpVersions orders numerically and handles prefixes and pre-releases', () => {
  assert.equal(cmpVersions('8.3.30', '8.3.36'), -1);
  assert.equal(cmpVersions('8.3.36', '8.3.30'), 1);
  assert.equal(cmpVersions('v7.4.0', '7.4.0'), 0);
  assert.equal(cmpVersions('1.10.0', '1.9.0'), 1);
  assert.equal(cmpVersions('1.0.0-rc1', '1.0.0'), -1);
  assert.equal(cmpVersions('1.0.0', '1.0.0-rc1'), 1);
  assert.equal(cmpVersions('4.2.0', '4.2.17'), -1);
  assert.equal(cmpVersions('2.0.0rc1', '2.0.0'), -1);
  assert.deepEqual(['7.4.5', '7.15.2', '7.4.3'].sort(cmpVersions), ['7.4.3', '7.4.5', '7.15.2']);
});

test('cvss3Score matches published base scores', () => {
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8);
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N'), 7.7);
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'), 7.5);
  assert.equal(cvss3Score('CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N'), 1.8);
  assert.equal(cvss3Score('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'), null);
});

test('prioritize: KEV listing is always P0, dev-only drops one level, fresh critical stays P0', () => {
  const base = { cvss: 5.0, severity: 'MEDIUM', published: '2023-01-01T00:00:00Z', dev: false, kev: null, epss: null, fixedVersion: '1.0.1', fixAvailable: true };
  assert.equal(prioritize(base).level, 'P2');
  assert.equal(prioritize({ ...base, kev: { dateAdded: '2026-10-20' } }).level, 'P0');
  assert.equal(prioritize({ ...base, kev: { dateAdded: '2026-10-20' }, dev: true }).level, 'P0', 'KEV beats dev-only');
  assert.equal(prioritize({ ...base, cvss: 9.8, dev: true }).level, 'P1');
  assert.equal(prioritize({ ...base, cvss: 7.5 }).level, 'P1');
  assert.equal(prioritize({ ...base, cvss: 7.5, published: new Date().toISOString() }).level, 'P0', 'fresh high is P0');
  assert.equal(prioritize({ ...base, epss: { epss: 0.5, percentile: 0.99 } }).level, 'P0');
  assert.equal(prioritize({ ...base, epss: { epss: 0.06, percentile: 0.93 } }).level, 'P1');
  assert.equal(prioritize({ ...base, cvss: 3.0 }).level, 'P3');
  const old = prioritize({ ...base, cvss: 5.4, emergencyRelease: '2026-10-21' });
  assert.equal(old.level, 'P2', 'an emergency release does not bump CVEs that are months old');
  const fresh = prioritize({ ...base, cvss: 5.4, published: new Date().toISOString(), emergencyRelease: '2026-10-21' });
  assert.equal(fresh.level, 'P1', 'but it does bump the CVEs it was shipped for');
  assert.ok(prioritize({ ...base, context: 'constraint' }).reasons.some((r) => /not pinned/.test(r)));
});

test('imageRuntimes reads official and vendor image tags', () => {
  assert.deepEqual(imageRuntimes('php:8.3.30-fpm-alpine'), [{ product: 'php', version: '8.3.30' }]);
  assert.deepEqual(imageRuntimes('php:8.3-fpm'), [{ product: 'php', version: '8.3' }]);
  assert.deepEqual(imageRuntimes('php:latest'), [{ product: 'php', version: null }]);
  assert.deepEqual(imageRuntimes('wordpress:6.5-php8.2-apache'), [{ product: 'wordpress', version: '6.5' }, { product: 'php', version: '8.2' }]);
  assert.deepEqual(imageRuntimes('docker.io/library/node:20.11-alpine'), [{ product: 'node', version: '20.11' }]);
  assert.deepEqual(imageRuntimes('serversideup/php:8.3-fpm'), [{ product: 'php', version: '8.3' }]);
  assert.deepEqual(imageRuntimes('ghcr.io/acme/api:latest'), []);
  assert.deepEqual(imageRuntimes('registry:5000/python:3.12.1-slim'), [{ product: 'python', version: '3.12.1' }]);
  assert.deepEqual(imageRuntimes('golang:1.22.1'), [{ product: 'go', version: '1.22.1' }]);
});

test('pnpm-lock.yaml v9', () => {
  const i = inv('pnpm-app');
  assert.equal(pkg(i, 'npm', 'lodash')?.version, '4.17.15');
  assert.equal(pkg(i, 'npm', '@babel/core')?.version, '7.24.0');
  assert.equal(pkg(i, 'npm', 'lodash').manager, 'pnpm');
});

test('yarn.lock v1 and berry', () => {
  const v1 = inv('yarn1-app');
  assert.equal(pkg(v1, 'npm', 'lodash')?.version, '4.17.15');
  assert.equal(pkg(v1, 'npm', '@types/node')?.version, '20.11.5');
  assert.equal(pkg(v1, 'npm', 'lodash').manager, 'yarn');
  const berry = inv('berry-app');
  assert.equal(pkg(berry, 'npm', 'lodash')?.version, '4.17.15');
  assert.equal(pkg(berry, 'npm', 'lodash').manager, 'yarn-berry');
});

test('poetry.lock and requires-python', () => {
  const i = inv('poetry-app');
  assert.equal(pkg(i, 'PyPI', 'django')?.version, '4.2.0', 'names are lower-cased for OSV');
  assert.equal(pkg(i, 'PyPI', 'requests')?.version, '2.25.0');
  const py = i.runtimes.find((r) => r.product === 'python');
  assert.equal(py?.version, '3.11'); assert.equal(py?.context, 'constraint');
});

test('Cargo.lock', () => {
  const i = inv('rust-app');
  assert.equal(pkg(i, 'crates.io', 'openssl')?.version, '0.10.55');
  assert.equal(i.packages.length, 2);
});

test('Gemfile.lock specs and Gemfile ruby pin', () => {
  const i = inv('ruby-app');
  assert.equal(pkg(i, 'RubyGems', 'rails')?.version, '7.0.4');
  assert.equal(pkg(i, 'RubyGems', 'actionpack')?.version, '7.0.4');
  assert.equal(pkg(i, 'RubyGems', 'nokogiri')?.version, '1.13.9-x86_64-linux');
  const rb = i.runtimes.find((r) => r.product === 'ruby');
  assert.equal(rb?.version, '3.2.2'); assert.equal(rb?.context, 'pin');
});

test('go.mod requires, indirect flag, and go directive', () => {
  const i = inv('go-app');
  const gin = pkg(i, 'Go', 'github.com/gin-gonic/gin');
  assert.equal(gin?.version, '1.7.0', 'leading v stripped');
  assert.equal(gin?.direct, true);
  assert.equal(pkg(i, 'Go', 'golang.org/x/net')?.direct, false);
  assert.equal(pkg(i, 'Go', 'github.com/stretchr/testify')?.version, '1.8.4', 'single-line require');
  assert.equal(i.runtimes.find((r) => r.product === 'go')?.version, '1.21.5');
});

test('docker-compose images, .tool-versions and CI workflow versions', () => {
  const i = inv('compose-app');
  const by = (p, ctx) => i.runtimes.filter((r) => r.product === p && r.context === ctx);
  assert.deepEqual(by('wordpress', 'deploy').map((r) => r.version), ['6.5']);
  assert.ok(by('php', 'deploy').some((r) => r.version === '8.2' && /docker-compose/.test(r.file)));
  assert.ok(by('php', 'deploy').some((r) => r.version === '8.3' && r.image === 'serversideup/php:8.3-fpm'));
  assert.deepEqual(by('nginx', 'deploy').map((r) => r.version), ['1.27.1']);
  assert.ok(by('node', 'pin').some((r) => r.version === '20.11.0' && r.file === '.tool-versions'));
  assert.ok(by('php', 'pin').some((r) => r.version === '8.3.30'));
  assert.ok(by('php', 'ci').some((r) => r.version === '8.3' && /workflows\/ci\.yml/.test(r.file)));
});

test('.csproj PackageReference skips MSBuild property versions', () => {
  const i = inv('dotnet-app');
  assert.equal(pkg(i, 'NuGet', 'Newtonsoft.Json')?.version, '12.0.1');
  assert.equal(i.packages.length, 1);
});

test('pom.xml literal versions only', () => {
  const i = inv('maven-app');
  assert.equal(pkg(i, 'Maven', 'org.apache.logging.log4j:log4j-core')?.version, '2.14.1');
  assert.equal(i.packages.length, 1);
});

test('package.json without a lockfile only reports exact pins and leaves a note', () => {
  const root = path.join(FIX, '..', '..', 'examples', 'node-app');
  const files = findManifests(root).filter((f) => f !== 'package-lock.json');
  const i = inventory(root, files);
  assert.equal(pkg(i, 'npm', 'express')?.version, '4.17.1');
  assert.ok(i.notes.some((n) => /no lockfile/.test(n)));
});

test('groupFindings takes the worst priority, unions CVEs and prefers a same-major fix', () => {
  const mk = (o) => ({ kind: 'package', ecosystem: 'PyPI', name: 'django', version: '4.2.0', file: 'requirements.txt', manager: 'pip', direct: true, dev: false, cves: [o.cve], id: o.cve, title: o.cve, priority: o.priority, priorityLabel: '', cvss: o.cvss, reasons: [`CVSS ${o.cvss}`], fixedVersion: o.fixed, fixedSameMajor: o.same, kev: null, ...o });
  const same = groupFindings([mk({ cve: 'CVE-1', priority: 'P2', cvss: 5, fixed: '4.2.17', same: '4.2.17' }), mk({ cve: 'CVE-2', priority: 'P0', cvss: 9.8, fixed: '4.2.30', same: '4.2.30' })]);
  assert.equal(same.length, 1);
  assert.equal(same[0].priority, 'P0');
  assert.equal(same[0].fixedVersion, '4.2.30');
  assert.equal(same[0].majorJump, false);
  assert.deepEqual(same[0].cves, ['CVE-2', 'CVE-1']);
  const jump = groupFindings([mk({ cve: 'CVE-1', priority: 'P1', cvss: 8, fixed: '4.2.30', same: '4.2.30' }), mk({ cve: 'CVE-3', priority: 'P1', cvss: 8.8, fixed: '5.2.17', same: null })]);
  assert.equal(jump[0].fixedVersion, '5.2.17');
  assert.equal(jump[0].majorJump, true);
  assert.equal(jump[0].partialFix.version, '4.2.30');
  assert.deepEqual(jump[0].partialFix.needsMajor, ['CVE-3']);
  assert.ok(LEVELS.includes(jump[0].priority));
});

test('.patchnow.json ignore prefixes keep demo projects out of the inventory', () => {
  const repoRoot = path.join(FIX, '..', '..');
  const files = findManifests(repoRoot);
  assert.ok(files.includes('package.json'), 'the repo root manifest is still found');
  assert.ok(!files.some((f) => f.startsWith('examples/') || f.startsWith('test/fixtures/')), `ignored paths leaked: ${files.filter((f) => /^(examples|test\/fixtures)\//.test(f)).join(', ')}`);
});
