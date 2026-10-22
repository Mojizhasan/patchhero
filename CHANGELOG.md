# Changelog

## 0.1.0 (2026-10-22)

First release, built the morning after PHP2Shell (CVE-2026-109618, CVE-2026-109619).

- Scanner: npm/pnpm/yarn, Composer, pip/Poetry/uv/PDM/Pipenv, Go, Cargo, Bundler, NuGet, Maven/Gradle lockfiles; Dockerfiles, compose files, version files, CI workflows; `--local` runtime probe.
- Feeds: OSV.dev, NVD (CPE, 120-day window), endoflife.date, CISA KEV, FIRST EPSS.
- Priority: P0 to P3 from CVSS, KEV, EPSS, disclosure age, emergency vendor releases, dev-only demotion.
- Output: grouped human report, `--json`, `--md`, `--hook`, `--fail-on` exit codes, multi-project folders.
- Siren: "spreading now" section from CISA alerts, KEV additions (3 days), Hacker News front page and Google News (48 hours), clustered by product, matched to the project and to the software everyone runs; a sixth priority signal; emergency mode re-checks hourly.
- Claude Code plugin with a SessionStart alert hook (cached per project, read-only) and the `/patchhero` skill.
- GitHub Actions workflow template with issue creation and an optional Claude autofix job.
