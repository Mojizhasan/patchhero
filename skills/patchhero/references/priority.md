# How patchhero decides what to patch first

The point of the priority score is to answer "what is getting traction right now?", not "what has the highest CVSS?". A ten-year-old critical CVE in a dev tool is not what people are scared of when a new exploit is in the news. The score combines five public signals; each one alone misses real cases.

## Signals

| Signal | Source | What it tells you | Why one signal is not enough |
| --- | --- | --- | --- |
| CVSS base score | NVD, GitHub Advisory Database via OSV | how bad it is if exploited | says nothing about whether anyone is exploiting it |
| CISA KEV | CISA Known Exploited Vulnerabilities catalog | confirmed exploited in the wild | lags disclosure by days or weeks; PHP2Shell was not in KEV the day after disclosure |
| EPSS | FIRST.org | probability of exploitation in the next 30 days | also lags: PHP2Shell scored 5% on day one |
| Disclosure age | advisory published date | fresh criticals draw attackers and press | old CVEs can still be exploited |
| Emergency vendor release | endoflife.date latest release date | the vendor broke its release cadence to ship a fix | only meaningful for the CVEs that release fixed |
| Spreading now (siren) | CISA alerts, KEV additions in the last 3 days, Hacker News front page, Google News headlines | the world is reacting: press, security teams, governments | news is noisy and names products, not versions; it is matched to this project's components and never used alone |

## Rules

Levels: **P0** patch today, **P1** patch this week, **P2** next release, **P3** backlog.

1. Start from CVSS: 9.0 and above is P0, 7.0 to 8.9 is P1, 4.0 to 6.9 is P2, below 4.0 is P3. No score at all starts at P2.
2. In CISA KEV: P0, always. Exploitation in the wild overrides everything, including the dev-only rule.
3. EPSS 30% or more: P0. EPSS 5% or more: at least P1.
4. Disclosed within the last 14 days and CVSS 7.0 or more: one level more urgent.
5. The vendor shipped a release in the last 14 days and the CVE itself is less than 30 days old: one level more urgent. Older CVEs on the same runtime are not bumped; the release was not for them.
6. Spreading now: a headline, CISA alert or fresh KEV entry names one of the finding's CVEs, or names the product while the CVE is under 30 days old: one level more urgent. The report's "spreading now" section lists what matched and the evidence (Hacker News points, number of headlines, CISA alert).
7. Dev-only dependency (test or build tooling): one level less urgent, unless in KEV.
8. Unpinned context (a composer.json constraint, `engines.node`, a CI matrix): the report adds "deployed version not pinned; verify on the server". Only hot CVEs (KEV, or CVSS 7+ and under 30 days old) are reported for unpinned contexts, otherwise every project that says `"php": "^8.2"` would drown in historical PHP CVEs.

## The siren: what is spreading, with or without this project

The "spreading now" section is independent of the findings. It clusters the last 48 hours of headlines (Hacker News stories with 30+ points, Google News, CISA alerts) and the last 3 days of KEV additions by the product or CVE they name, then keeps three kinds:

- **affects this project**: the cluster names a runtime, ecosystem or package this project uses;
- **not in this repo, but on your servers and laptop**: it names software nearly everyone runs (operating systems, CPUs, OpenSSL, OpenSSH, Docker, browsers, Cloudflare, AWS); the fix is an OS or firmware update where the app runs, not a change in the repo;
- **everyone is talking about it**: a front-page story (500+ Hacker News points, 8+ headlines, or CISA alert plus KEV) about something else entirely. One line, so nobody learns about the next Log4Shell from a customer.

A cluster that touches the project with strong evidence, or a universal one backed by CISA or KEV, puts the session-start hook into emergency mode: it re-checks every hour instead of every six. The queries are fixed strings; nothing about the project is sent to any news source. `--news` shows every cluster, `--no-news` turns the feeds off.

A component's priority is its worst finding's priority. The recommended version is the smallest upgrade that closes every advisory on the current major; when some advisory is only fixed on a newer major line, the report says so and shows what the current line can still fix.

## Worked example: PHP2Shell, 22 October 2026

CVE-2026-109618 and CVE-2026-109619 were disclosed on 21 October 2026 with fixes in PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35. The next morning:

- CVSS 9.2 → P0 by rule 1
- Not in KEV yet (CISA had not observed exploitation at publication) → rule 2 silent
- EPSS 5.3% → rule 3 gives at least P1, not P0
- Disclosed yesterday → rule 4
- PHP shipped four emergency releases the same day → rule 5

A KEV-only or EPSS-only tool would have called this "medium, watch". patchhero called it P0 for a `FROM php:8.3.30-fpm` Dockerfile and for a composer.json requiring `^8.2`, with the fixed versions listed. That is the gap this skill exists to close.

## Explaining a priority to someone without a security background

Say what the component is, in which file, then one sentence per reason in plain words:

- "CVSS 9.2 critical" → "rated critical: an attacker on the internet could run code on your server without logging in"
- "in CISA KEV" → "the US government has confirmed attackers are using this one right now"
- "EPSS 19%" → "about a one-in-five chance this gets exploited in the next month, which is very high"
- "disclosed yesterday" → "this is brand new, so attackers and scanners are looking for it"
- "vendor shipped an emergency release" → "PHP pushed an unscheduled fix, which they only do for serious bugs"
- "dev-only dependency" → "only used while building or testing, not on the live site, so it can wait"
