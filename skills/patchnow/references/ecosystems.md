# Applying package upgrades per ecosystem

The report's `$` lines are the primary instruction; this file is for what goes wrong and what to check. In every ecosystem: upgrade, regenerate the lockfile, run the tests, re-scan.

## npm / pnpm / yarn

- **Direct dependency**: `npm install <pkg>@<fixed>` (pnpm: `pnpm up <pkg>@<fixed>`, yarn berry: `yarn up`, yarn v1: `yarn upgrade`). This rewrites package.json and the lockfile together.
- **Transitive dependency** (the report says `overrides` / `resolutions`): add the override block to package.json, then run the install command so the lockfile picks it up. Overrides force a version the parent package did not ask for, so run the tests. If a parent package has its own newer release that already requires the fixed version, upgrading the parent is cleaner than an override.
- `npm audit fix` is a fine shortcut for small sets, but it does not know about priority; prefer targeted upgrades for P0.
- Before installing the recommended version, run `npm view <pkg>@<version> deprecated`. Registries occasionally mark a fixed release as a bad release (lodash 4.18.0 was deprecated the day after it shipped); if so, take the next release on the same line and confirm with the scanner that it is clean.
- A hand-written or truncated lockfile can hide a package's real dependency tree. If the first install adds many entries to the lockfile, re-scan: new transitive findings may appear, and upgrading the parent package (Express 4.17 → 4.22 pulls in fixed qs, body-parser, path-to-regexp, send, serve-static, cookie) is cleaner than a pile of overrides.
- A major upgrade (`4.x → 5.x`) can change APIs. Check the package's changelog or migration guide before committing; offer the same-line version the report shows as a stopgap.
- The scan reads package-lock.json, npm-shrinkwrap.json, pnpm-lock.yaml and yarn.lock. With only a package.json, only exact pins are known: run the install once to create a lockfile, then re-scan.

## Composer (PHP packages)

- `composer require <vendor>/<pkg>:^<fixed> --update-with-all-dependencies` for direct dependencies; `composer update <vendor>/<pkg> --with-all-dependencies` for transitive ones.
- A failing resolution usually means the project's PHP constraint (`"php": "^8.1"` in composer.json or `config.platform.php`) is too old for the fixed release. Raise the constraint only if the server really runs that PHP version; see runtimes.md.
- Composer versions in composer.lock carry a leading `v` (`v6.4.0`); the scanner strips it.
- Laravel, Symfony and WordPress plugins pin frameworks tightly; an upgrade of one package may need a framework patch release too. `composer why-not <pkg> <version>` explains the block.

## Python (pip, Poetry, uv, Pipenv, PDM)

- requirements.txt: change the pin to `pkg==<fixed>` (or `>=<fixed>` if the file uses ranges), then `pip install -r requirements.txt`. Keep hashes (`--hash=`) in sync if the file uses them: `pip-compile` regenerates them.
- Poetry: `poetry add "pkg>=<fixed>"` then `poetry lock`. uv: `uv add "pkg>=<fixed>"`. Pipenv: `pipenv install "pkg>=<fixed>"`. PDM: `pdm add "pkg>=<fixed>"`.
- Package names are case-insensitive and `_`/`-` interchangeable; the scanner lower-cases them for OSV.
- A fix on a newer major (Django 4.2 → 5.2) is a real migration: read the release notes, check `python_requires`, and tell the user what the current line can still fix.
- The project's Python version matters: a fixed release may drop support for an old interpreter. runtime.txt, .python-version and `requires-python` are read by the scanner.

## Go

- `go get <module>@v<fixed> && go mod tidy`. Indirect modules (`// indirect`) upgrade the same way.
- Go stdlib vulnerabilities are matched against the `go`/`toolchain` directive in go.mod; the fix is a newer Go toolchain, see runtimes.md.
- `govulncheck ./...` (if installed) tells you whether the vulnerable function is actually called; use it to justify leaving a P2 alone, never to skip a P0.

## Rust

- `cargo update -p <crate> --precise <fixed>`. If another crate pins the old version, `cargo tree -i <crate>` shows who; upgrade that parent.
- A fix on a newer major may need code changes; `cargo build` tells you immediately.

## Ruby

- `bundle update <gem> --conservative` keeps everything else unchanged. If Bundler refuses, a parent gem pins it: `bundle exec gem dependency <gem> --reverse-dependencies`.
- Platform-specific versions like `1.13.9-x86_64-linux` are reported as-is; the fix version applies to all platforms.
- Rails upgrades across minors need `rails app:update`; prefer the latest patch on the current minor for P0.

## .NET

- `dotnet add <project> package <pkg> --version <fixed>`; with central package management edit Directory.Packages.props instead. Then `dotnet restore --force-evaluate` if packages.lock.json exists.
- Versions coming from MSBuild properties (`$(SomeVersion)`) are not scanned; look at the props file by hand if the report mentions nothing for a package you know is there.

## Java

- Maven: set the `<version>` in pom.xml (or the property it points to) and run `mvn -q verify`. Gradle: change the dependency string and `./gradlew dependencies --write-locks` if lockfiles are used.
- Only literal versions in pom.xml and `gradle.lockfile` entries are scanned; versions set in a parent POM or BOM are invisible to the scan. Say so when a Java project reports suspiciously few packages.

## After any upgrade

1. Re-run the scanner with `--min P1`; the component should be gone or lower.
2. Run the project's tests or build.
3. Commit the manifest and lockfile together; a lockfile-only diff is a sign the manifest still allows the vulnerable version.
