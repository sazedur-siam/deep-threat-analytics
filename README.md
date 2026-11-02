# Deep Threat Analytics

[![CI](https://github.com/sazedur-siam/deep-threat-analytics/actions/workflows/ci.yml/badge.svg)](https://github.com/sazedur-siam/deep-threat-analytics/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/sazedur-siam/deep-threat-analytics/blob/main/LICENSE)

**See what your dependencies actually do, not just which CVEs they have.**

Deep Threat Analytics is a Visual Studio Code extension that reads the source code of the packages installed in your project. It flags behavior that could compromise your machine or leak data: sending environment variables over the network, reading SSH keys or cloud credentials, spawning shells, running obfuscated code, or hooking into install scripts.

Its rules, allowlists, severities and policies are all yours to customize.

> **Status: early development.** The extension is not yet on the Visual Studio Marketplace. The features below describe the planned 0.1.0 pre-release. See [Roadmap](#roadmap) for what is finished.

## Why another dependency scanner?

Vulnerability scanners match package versions against databases of _known_ CVEs. That misses:

- **Malicious packages** that have not been reported yet, such as typosquats, hijacked maintainers, and protestware.
- **Install-time attacks**: `postinstall` scripts, `setup.py` code, and `.pth` files that run as soon as you install.
- **Risky capabilities** in packages you trust, such as a date library that opens network sockets.

Deep Threat Analytics looks at the code itself, entirely on your machine. When you opt in, it adds CVE and package-reputation checks on top.

## What it detects

| Category      | Examples                                                                                                       |
| ------------- | -------------------------------------------------------------------------------------------------------------- |
| Exfiltration  | Reading `process.env` / `os.environ` or secret files **and** sending data over the network                     |
| Secrets & FS  | Access to `~/.ssh`, `~/.aws/credentials`, `~/.npmrc`, `.env`, browser cookie stores, the keychain              |
| Exec          | `child_process.exec`, `subprocess` with `shell=True`, reverse-shell patterns                                   |
| Dynamic code  | `eval` / `new Function` / `exec` on non-literal input, `marshal.loads`, `pickle.loads`                         |
| Obfuscation   | High-entropy base64/hex payloads that get decoded and executed, javascript-obfuscator signatures               |
| Install hooks | npm `preinstall` / `install` / `postinstall` scripts, code in `setup.py`, executable `.pth` files              |
| Network       | Webhook and paste endpoints (Discord, Telegram, pastebin), raw sockets, DNS exfiltration, raw IPs              |
| Persistence   | Writes to shell profiles, crontab, LaunchAgents, systemd units, Windows Run keys                               |
| Crypto mining | Mining pool URLs, miner binaries, crypto-wallet file access                                                    |
| Reputation    | Typosquatted names (offline); optional checks for brand-new, deprecated or yanked packages, maintainer changes |
| Vulnerability | Known CVEs and malicious-package advisories from [OSV.dev](https://osv.dev) (opt-in)                           |

Correlation reduces noise. A package that only makes HTTP requests is reported as _info_. A package that reads your credentials **and** posts them to a webhook is reported as _critical_.

## Supported ecosystems

| Ecosystem                             | Manifests                                                         | Status  |
| ------------------------------------- | ----------------------------------------------------------------- | ------- |
| npm / pnpm / Yarn (classic and Berry) | `package.json` + lockfile                                         | Phase 1 |
| Python (pip, Poetry, uv)              | `requirements*.txt`, `pyproject.toml`, `poetry.lock`, `uv.lock`   | Phase 1 |
| Go                                    | `go.mod`                                                          | Phase 2 |
| Rust (Cargo)                          | `Cargo.toml`                                                      | Phase 2 |
| Java (Maven / Gradle)                 | `pom.xml`, `build.gradle(.kts)` (scans `-sources.jar` if present) | Phase 2 |
| PHP (Composer)                        | `composer.json`                                                   | Phase 2 |

## Usage

Scans run only when you ask for one, never automatically on open or save:

- **Command Palette** → `DepThreat: Scan Workspace`
- Right-click a manifest in the Explorer or editor → `DepThreat: Scan This Manifest`

Results appear in three places:

- **Inline diagnostics** on each dependency in the manifest. Hover for a summary.
- **Quick Fixes**: open the offending source line, ignore a rule for a package, allowlist a package, or bump to a fixed version.
- **The Deep Threat Analytics sidebar**: Manifest › Package › Finding › exact line in the dependency's code. Policy violations are grouped separately.

## Privacy and data

- **Code analysis is 100% local.** Dependency files are read from disk and never uploaded, and dependency code is **never executed**.
- **Online lookups are off by default.** When you enable them:
  - `depthreat.online.osv.enabled` sends package **name, ecosystem and version** to `api.osv.dev`.
  - `depthreat.online.registryMetadata.enabled` sends package **names** to `registry.npmjs.org` / `pypi.org`.
- **No telemetry** is collected.

### Workspace Trust

In an untrusted workspace the extension runs in restricted mode:

- It does not run the Python interpreter to locate `site-packages`, and only looks for a `.venv` on disk.
- It ignores workspace-level values for rule paths, the interpreter path, and online lookups. Only your user settings apply.

## Configuration

### Settings

| Setting                                     | Default               | Description                                                    |
| ------------------------------------------- | --------------------- | -------------------------------------------------------------- |
| `depthreat.scanTransitive`                  | `true`                | Also scan dependencies of dependencies                         |
| `depthreat.includeDevDependencies`          | `false`               | Scan dev/test dependencies                                     |
| `depthreat.minSeverity`                     | `low`                 | Hide findings below this severity                              |
| `depthreat.severityMapping`                 | critical/high → Error | How each severity is shown (Error, Warning, Information, Hint) |
| `depthreat.exclude`                         | `node_modules`, venvs | Glob patterns for manifests to skip                            |
| `depthreat.maxFileSizeKB`                   | `1024`                | Skip larger files                                              |
| `depthreat.maxFilesPerPackage`              | `2000`                | Per-package file cap                                           |
| `depthreat.concurrency`                     | `4`                   | Packages scanned in parallel                                   |
| `depthreat.rulesPaths`                      | `[]`                  | Extra folders with custom rule files                           |
| `depthreat.python.interpreterPath`          | `""`                  | Python interpreter used to find `site-packages`                |
| `depthreat.online.osv.enabled`              | `false`               | Query OSV.dev for known vulnerabilities                        |
| `depthreat.online.registryMetadata.enabled` | `false`               | Check npm/PyPI metadata (age, deprecation, maintainers)        |

### Project config: `.depthreat/config.yaml`

Commit this file to share allowlists, ignores and policies with your team:

```yaml
allowlist:
  packages: ['esbuild', '@types/*', 'pypi:requests']
  rules: ['obfuscation/minified-eval']

ignore:
  - { package: 'lodash', rule: 'obfuscation/*', reason: 'minified dist' }
  - { finding: 'a1b2c3d4e5f60718', reason: 'reviewed by security team' }

severityOverrides:
  - { rule: 'network/*', severity: low }

policies:
  - { name: no-install-hooks, deny: { category: install-hook }, action: error }
  - {
      name: no-network-in-crypto,
      packages: ['*crypto*'],
      deny: { category: [network, exfiltration] },
      action: error,
    }
  - { name: no-critical, deny: { minSeverity: critical }, action: error }
```

Policy violations are shown as errors, collected in their own sidebar group, and turn the status bar red.

### Custom rules: `.depthreat/rules/*.yaml`

Custom rules use the same format as the built-in ones. A rule with the same `id` as a built-in rule replaces it, and `enabled: false` turns it off.

```yaml
- id: custom/internal-telemetry-endpoint
  title: Talks to an unapproved endpoint
  category: network
  severity: high
  languages: [javascript, typescript, python]
  match:
    any:
      - regex: 'https?://[a-z0-9.-]*\.example\.invalid'
    not:
      - regex: '^\s*(//|#)'
    scope: line # line | file | package
  message: '{package} contacts an unapproved host in {file}'
```

- `all`: every pattern must match within the `scope`.
- `any`: at least one pattern must match.
- `not`: vetoes the match.
- `scope: file` or `scope: package` lets you correlate signals, for example "reads env vars" **and** "makes HTTP requests" in the same file.

### Inline ignores

```text
# requirements.txt
somepkg==1.2.3  # depthreat-ignore
otherpkg>=2     # depthreat-ignore[exec/python-shell, obfuscation/*]
```

```jsonc
// package.json (JSON has no comments, so use a top-level field)
"depthreat": { "ignore": { "some-package": ["network/*"], "other-package": "all" } }
```

## Roadmap

- [x] Project scaffold, test tooling (unit + VS Code integration), CI
- [x] Core types, rule schema and loader with user overrides
- [x] Scan cache and concurrency helpers
- [ ] npm / pnpm / Yarn adapter
- [ ] Python adapter
- [ ] Code scanner, obfuscation and install-hook detection, built-in rule packs
- [ ] Project config, ignores, allowlists and policy gates
- [ ] Scan engine
- [ ] Diagnostics, hovers, Quick Fixes, sidebar, status bar
- [ ] OSV.dev and reputation checks
- [ ] 0.1.0 pre-release on the Visual Studio Marketplace
- [ ] Phase 2: Go, Rust, Java, PHP

## Development

Requirements: Node.js 20+ and VS Code 1.90+.

```bash
npm ci
npm run build              # bundle to dist/extension.js
npm run check              # typecheck + lint + format check + unit tests with coverage
npm run test:integration   # run integration tests inside VS Code
npm run package            # build a .vsix
```

Press **F5** in VS Code to launch an Extension Development Host.

Project layout:

```text
src/core/       engine, shared types, cache (no VS Code API, fully unit-tested)
src/adapters/   one adapter per ecosystem (manifest parsing, lockfiles, installed files)
src/scanners/   code patterns, obfuscation, install hooks, OSV, reputation
src/rules/      rule schema and loader
rules/builtin/  built-in rule packs (YAML)
src/config/     settings and .depthreat/config.yaml
src/policy/     ignores, allowlists, policy gates
src/ui/         diagnostics, hovers, Quick Fixes, tree view, status bar
test/           unit tests, VS Code integration tests, fixtures
```

Test fixtures contain **fake** packages with harmless code that only imitates suspicious patterns. Never add real malware.

### Contributing

Issues and pull requests are welcome. Please:

- use [Conventional Commits](https://www.conventionalcommits.org/) (`feat(npm): …`, `fix(scanner): …`),
- keep commits small and focused,
- make sure `npm run check` passes.

## License

[MIT](https://github.com/sazedur-siam/deep-threat-analytics/blob/main/LICENSE)
