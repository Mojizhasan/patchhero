---
name: patchnow
description: Find and patch the vulnerabilities that are getting traction right now (CISA KEV listings, high EPSS, fresh critical CVEs, emergency vendor releases such as PHP2Shell CVE-2026-109618/109619) across a project's dependencies (npm, pnpm, yarn, Composer, pip, Poetry, uv, Go, Cargo, Bundler, NuGet, Maven) and runtimes (PHP, Node.js, Python, Ruby, Go, nginx, WordPress found in Dockerfiles, compose files, version files, composer.json, package.json and CI). Use this whenever the user mentions a CVE, a vulnerability, a security advisory or exploit in the news, asks "is my project affected", "am I vulnerable", "patch this", "upgrade for security", "security update", sees a patchnow alert at session start, wants a security check before deploying, or wants automatic or scheduled security patching for one repo or all their repos. Use it even when no package is named and even when the user has no security background. Also use it to scan a whole folder of projects at once.
---

# patchnow

You are helping someone keep their project safe from the vulnerabilities that matter *right now*. Many people using this have no security background: they heard about a scary bug on the news and want to know "am I affected, and what do I do?". The scanner does the hard part (inventory, five public vulnerability feeds, a priority score). Your job is to turn its report into applied, verified patches without surprising anyone.

## Run the scan

The scanner is `scripts/scan.mjs`, next to this file. Node 18+ only, nothing to install, read-only.

```bash
node "<this skill's directory>/scripts/scan.mjs" "<project directory>" --local
```

When installed as a plugin the path is `${CLAUDE_PLUGIN_ROOT}/skills/patchnow/scripts/scan.mjs`. When the session-start alert gave you a "Full report:" command, run exactly that.

Useful flags:

| Flag | Use it when |
| --- | --- |
| `--local` | also check the PHP/Node/Python/Ruby/Go installed on this machine (the developer's own box is a target too) |
| `--json` | you need to look something up (a CVE, a package) rather than read the report |
| `--md` | you are writing an issue or PR body |
| `--min P1` | the full list is long and the user only cares what is urgent |
| `--all` | the directory is a folder of projects (`~/projects`), to get one table across all of them |
| `--fail-on P0` | CI: exit code 2 when something must be patched today |
| `--offline` | the network is down; uses cached feed data |

A project can exclude directories (demo apps, fixtures, vendored code) with a `.patchnow.json` at its root: `{ "ignore": ["examples", "test/fixtures"] }`. Suggest it when a scan is dominated by findings in directories that are clearly not the deployed app.

The report groups by component: one line per package@version or runtime reference, with the worst CVE, how many more it fixes, the reasons for its priority, and the exact command. Priority levels are P0 patch today, P1 this week, P2 next release, P3 backlog. Read `references/priority.md` when you need to explain *why* something is P0 or when the user disagrees with a priority.

## Workflow

1. **Scan, then translate.** Show the P0 and P1 items first, in plain words: what component, why now (quote the report's reasons, for example "CVSS 9.2, disclosed yesterday, vendor shipped an emergency release"), and what the fix is. Someone without a security background needs what/why/how, not a wall of CVE IDs. If nothing is P0/P1, say so clearly and mention how many P2/P3 remain.
2. **Confirm before changing anything.** Ask "Patch the N urgent items now?" unless the user already told you to go ahead or you are running in CI. A session-start alert is information, not consent. Never patch silently.
3. **Patch from the top down**, using the exact command the report gives. Each ecosystem has its own gotchas (transitive dependencies, lockfile regeneration, constraints that block the upgrade): read `references/ecosystems.md` before your first package upgrade in a session. Runtimes are different: a PHP or Node version in a Dockerfile, a version file, or composer.json describes where the app *should* run, and the real fix often happens on a server, a hosting panel or a container image. Read `references/runtimes.md` before touching a runtime finding, and always tell the user where the upgrade actually has to happen.
4. **Verify.** Re-run the scan (`--min P1`). Run the project's own tests or build if it has any (`npm test`, `composer test`, `pytest`, `go test ./...`). A fix that breaks the build is not a fix; if an upgrade breaks something, say so and offer the smallest version that still closes the urgent CVEs (the report prints "X on your current line fixes a/b" when a major jump is needed).
5. **Deliver.** In a git repository, work on a branch named `patchnow/<YYYY-MM-DD>` with one commit per component (or one commit for a small set), and offer to open a pull request whose body is the `--md` report. Do not push or open the PR unless asked.

End with a short summary in this shape:

```
Patched (verified by re-scan): guzzlehttp/guzzle 7.4.0 → 7.15.2 (14 advisories), lodash 4.17.15 → 4.18.0
Needs you: PHP 8.3.30 → 8.3.36 on the server (Dockerfile updated; rebuild and redeploy)
Left alone: phpunit (dev-only, P2); django needs the 5.2 line, which is a major upgrade
```

## "Am I affected by X?"

Run the scan with `--json` and search it for the CVE id, the package, or the product. Three outcomes:

- **Found**: explain the finding and offer the patch.
- **Component present, CVE not listed**: say that the feeds (OSV, NVD) can lag a few hours behind a disclosure. If the CVE is less than a day old, fetch the vendor advisory or the NVD page for the CVE and compare the affected version ranges to the inventory yourself.
- **Component not in the inventory**: the project does not appear to use it. Check the inventory counts in the report header; with no lockfile only exact pins are known, and the report says so in a note.

## Automatic patching for every project

When the user wants this to "just happen" for all their projects, there are three layers. Say which ones they already have.

- **Session-start alert**: included with the plugin install (a SessionStart hook that runs the scanner, cached for six hours, read-only). Installed as a bare skill, there is no hook: offer to add one to `~/.claude/settings.json`:
  ```json
  { "hooks": { "SessionStart": [{ "matcher": "startup|resume|clear|compact", "hooks": [{ "type": "command", "command": "node \"<skill dir>/scripts/scan.mjs\" --hook", "timeout": 30 }] }] } }
  ```
- **Scheduled scan in GitHub Actions**: copy `assets/patchnow.yml` into the repo as `.github/workflows/patchnow.yml`. It runs every six hours, writes the report to the job summary, opens or updates an issue labelled `patchnow` when P0/P1 findings exist, and fails the job on P0 so the repo shows red. The file also contains a commented job that lets Claude Code open the fix PR automatically; it needs an `ANTHROPIC_API_KEY` secret, so explain that before enabling it. The workflow fetches the scanner from the public patchnow repository at run time; if that is unreachable from the runner, vendor `scripts/scan.mjs` into the repo as `.github/patchnow/scan.mjs` and point the two `node` steps at it (the file's header comment shows how). Warn that GitHub pauses schedules in public repos after 60 days without commits (pushes still trigger it, and one click re-enables it). For many repos, the same file goes into each one; nothing else is per-repo.
- **Many local projects**: `scan.mjs ~/projects --all` gives one table across every project; offer to patch the P0 projects one at a time.

## Honesty rules

- The report is only as good as the inventory. No lockfile means only exactly pinned versions were checked; a constraint like `^8.2` or `engines.node >=18` does not say what is deployed. Repeat the report's notes to the user instead of hiding them.
- Do not say "patched" until the re-scan shows the finding gone. When it cannot go (end-of-life line, no upstream fix, major upgrade needed), say exactly that and what the user can do instead (WAF rule, disable the feature, plan the major upgrade).
- Never lower a priority to make the summary look better, and never apply a fix the user did not agree to.
- Only package names and versions leave the machine (to OSV.dev); the feeds are public and free. Say so if the user asks what is being sent.
