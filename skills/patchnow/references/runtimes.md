# Patching runtimes (PHP, Node.js, Python, Ruby, Go, nginx, WordPress)

A runtime finding is different from a package finding: the file in the repo (Dockerfile, .nvmrc, composer.json) says what the app *expects*, but the vulnerable binary lives on a server, in a container image, in a hosting plan, or on the developer's laptop. Editing the repo is half the job. Always tell the user where the other half happens, and never report a runtime finding as "patched" because a file changed.

The report labels each runtime reference with a context:

| Context | Where it came from | What "patched" means |
| --- | --- | --- |
| `deploy` | `FROM php:8.3.30-fpm` in a Dockerfile, `image:` in compose | change the tag (or rebuild with `--pull` for floating tags like `php:8.3`), rebuild, redeploy, then `php -v` inside the running container |
| `pin` | .php-version, .nvmrc, .python-version, .tool-versions, runtime.txt, go.mod `go`/`toolchain`, Gemfile `ruby` | change the pin, then reinstall locally (nvm/pyenv/asdf), and make sure CI and hosting read the same file |
| `constraint` | composer.json `"php": "^8.2"`, package.json `engines.node`, pyproject `requires-python` | nothing to patch in the repo; check and upgrade the deployed runtime; raise the constraint only to stop deploys on old versions |
| `implied` | a composer.json with no php constraint | same as constraint |
| `ci` | `php-version: '8.3'` in a workflow | CI installs the newest patch itself; only flagged when the whole line is end-of-life |
| `local` | `php -v` on this machine (`--local`) | upgrade the machine: winget/choco/installer on Windows, `brew upgrade` on macOS, apt/dnf or a version manager on Linux |

## PHP

- **Official Docker images**: `php:8.3.36-fpm`, `php:8.3.36-apache`, `php:8.3.36-cli`, Alpine variants. A floating tag like `php:8.3-fpm` already points at the fixed release once Docker Hub rebuilds it (hours after php.net); the fix is `docker build --pull` and redeploy, and pinning the full version in the Dockerfile so the next scan can verify it.
- **Vendor images** (`serversideup/php`, `bitnami/php-fpm`, `webdevops/php-nginx`): they rebuild on their own schedule; check the image's tags page for the fixed PHP version before relying on `--pull`.
- **Debian/Ubuntu servers**: `apt update && apt upgrade php8.3*` when using the distro or the Sury/Ondřej PPA packages, then restart FPM (`systemctl restart php8.3-fpm`) and the web server. Distro packages sometimes backport the fix without changing the version number: `apt changelog php8.3-fpm` or the distro security tracker says whether the CVE is fixed.
- **Managed hosting** (cPanel, Plesk, Laravel Forge, Ploi, Cloudways, Kinsta, WP Engine, Hostinger and the like): the PHP version is a dropdown in the control panel. Tell the user to pick the fixed patch release (8.3.36 or newer) and that shared hosts often apply it for everyone; `php -v` or `<?php phpinfo();` confirms it.
- **Platform hosts** (Heroku, Render, Fly.io, Vercel PHP runtimes, Laravel Cloud): the platform picks the patch release when the app is redeployed; a redeploy after the vendor updates their images is the fix, and composer.json's `php` constraint decides which line.
- **End-of-life lines** (8.1 and older as of 2026): no fix exists. The CISA advice for PHP2Shell was to take unfixable systems offline. Say that plainly, then plan a move to a supported line.
- Verify with `php -v` wherever the app actually runs. For FPM behind nginx, the CLI and FPM binaries can differ: `php-fpm8.3 -v` or a phpinfo page.

## Node.js

- Dockerfile `FROM node:20.11-alpine` → the fixed tag the report shows; floating `node:20` picks it up with `--pull`.
- .nvmrc / .node-version / .tool-versions → the new version, then `nvm install` (or `fnm`/`asdf`). CI `setup-node` reads .nvmrc when `node-version-file` is set.
- Serverless and PaaS (Vercel, Netlify, AWS Lambda, Cloud Functions) choose the patch release themselves within the selected major; a redeploy after the platform updates is the fix. An end-of-life major (Node 18 and 20 as of 2026) must be bumped in the platform settings or `engines.node`.
- `engines.node: ">=18"` is a constraint, not a version; raise it to the lowest supported line so deploys fail loudly on old runtimes.

## Python

- Dockerfile `FROM python:3.12.1-slim` → fixed tag; `python:3.12-slim` floats.
- .python-version / runtime.txt (Heroku-style `python-3.12.1`) → fixed version, then `pyenv install` or a fresh virtualenv.
- System Python on Debian/Ubuntu is patched through apt with backported fixes; check the distro tracker rather than the version number.

## Ruby

- Gemfile `ruby "3.2.2"` and .ruby-version → fixed version; `rbenv install` / `asdf install ruby`. Docker: `ruby:3.2.x` tags.

## Go

- `go.mod` `go 1.21.5` / `toolchain go1.21.5` → fixed version; `go get go@<fixed>` or `go get toolchain@go<fixed>` in Go 1.21+, then rebuild and redeploy the binaries. A Go runtime CVE is in the binaries you ship, so every deployed binary needs a rebuild.

## nginx

- Docker `nginx:1.27.1` → fixed tag; apt/dnf on servers (`nginx -v` to check). nginx mainline and stable have separate lines; end-of-life mainline versions need a move to the current stable.

## WordPress

- `wordpress:6.5-php8.2` images carry both WordPress and PHP versions; the report lists both. WordPress core updates from the admin dashboard or `wp core update`; the image tag must still be bumped so fresh containers are not old.

## What to tell the user, every time

1. Which file was changed in the repo (or that nothing in the repo needed to change).
2. Where the real upgrade happens (container rebuild, server package, hosting panel, laptop) and the one command or click that does it.
3. How to confirm: `php -v`, `node -v`, `python --version`, `ruby -v`, `go version`, `nginx -v`, run where the app runs.
4. That the scan can only verify the repo; the server has to be checked by hand or by running the scanner with `--local` on that machine.
